#include "dots.h"
#include "dots_policy.h"
#include "ankah/files.h"
#include "ankah/proxy.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#if defined(MBEDTLS_PSA_CRYPTO_C)
#include <psa/crypto.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DOTS_QUEUE 64
#define DOTS_ACLS 256
#define DOTS_REQUEST_MAX 4096
#define DOTS_RESPONSE_MAX (64U * 1024U)
#define DOTS_CIPHER_MAX (256U * 1024U)
#define DOTS_TIMEOUT_MS 5000
#define DOTS_SWEEP_MS 1000
#define DOTS_RETRY_NS (UINT64_C(5) * 1000000000U)
#define DOTS_REGISTER_BACKOFF_MAX_MS 30000U
#define SECOND_NS UINT64_C(1000000000)

typedef struct {
    int type;
    char name[ANKAH_DOTS_NAME_MAX];
    char ip[64];
} dots_op;

enum { ACL_FREE, ACL_INSTALLING, ACL_ACTIVE, ACL_WITHDRAWING };

typedef struct {
    int state;
    char ip[64];
    char name[ANKAH_DOTS_NAME_MAX];
    uint64_t expires_ns;
} dots_acl;

typedef struct {
    uv_tcp_t tcp;
    uv_timer_t timer;
    uv_connect_t connect;
    unsigned int handles;
    mbedtls_ssl_context ssl;
    int ssl_ready, handshaken, finished, eof;
    unsigned int writes_pending;
    unsigned char *cipher;
    size_t cipher_size, cipher_offset;
    char request[DOTS_REQUEST_MAX];
    size_t request_size, request_sent;
    char response[DOTS_RESPONSE_MAX];
    size_t response_size;
    dots_op op;
} dots_conn;

typedef struct {
    uv_write_t request;
    uv_buf_t buffer;
    dots_conn *conn;
} dots_write;

static struct {
    /* configuration */
    int enabled;
    char server_ip[64];
    int server_port;
    char server_name[256];
    char path[128];
    char ca_file[512], cert_file[512], key_file[512];
    char cuid[64];
    char protected_network[80];
    unsigned int protected_port;
    unsigned int threshold;
    unsigned int window_seconds;
    unsigned int block_seconds;
    /* runtime */
    uv_loop_t *loop;
    struct sockaddr_storage address;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_x509_crt ca, certificate;
    mbedtls_pk_context key;
    mbedtls_ssl_config tls;
    int tls_ready;
    ankah_dots_tracker tracker;
    dots_op queue[DOTS_QUEUE];
    unsigned int queue_head, queue_count;
    dots_acl acls[DOTS_ACLS];
    dots_conn *current;
    uv_timer_t sweep;
    int sweep_initialized;
    int registered, register_queued, closing;
    unsigned int register_backoff_ms;
    uint64_t register_retry_ns;
    ankah_dots_counters counters;
} dots;

static const char *const operation_names[ANKAH_DOTS_OPS] = {
    "register", "list", "install", "withdraw"
};

const char *ankah_dots_operation_name(int operation) {
    return operation >= 0 && operation < ANKAH_DOTS_OPS ? operation_names[operation] : "";
}

static int copy_value(char *out, size_t capacity, const char *value) {
    size_t size = strlen(value);
    if (!size || size >= capacity) return -1;
    memcpy(out, value, size + 1);
    return 0;
}

static int bounded_unsigned(const char *value, unsigned int low, unsigned int high,
                            unsigned int *out) {
    char *end;
    unsigned long parsed;
    if (!*value || *value == '-' || *value == '+') return -1;
    parsed = strtoul(value, &end, 10);
    if (*end || parsed < low || parsed > high) return -1;
    *out = (unsigned int)parsed;
    return 0;
}

static int parse_server(const char *value) {
    const char *colon, *start = value, *end;
    char *number_end;
    long port;
    size_t length;
    if (value[0] == '[') {
        start = value + 1;
        end = strchr(start, ']');
        if (!end || end[1] != ':') return -1;
        colon = end + 1;
    } else {
        colon = strrchr(value, ':');
        if (!colon || memchr(value, ':', (size_t)(colon - value))) return -1;
        end = colon;
    }
    length = (size_t)(end - start);
    if (!length || length >= sizeof(dots.server_ip)) return -1;
    memcpy(dots.server_ip, start, length);
    dots.server_ip[length] = 0;
    port = strtol(colon + 1, &number_end, 10);
    if (*number_end || port < 1 || port > 65535) return -1;
    dots.server_port = (int)port;
    if (uv_ip4_addr(dots.server_ip, dots.server_port,
                    (struct sockaddr_in *)&dots.address) != 0 &&
        uv_ip6_addr(dots.server_ip, dots.server_port,
                    (struct sockaddr_in6 *)&dots.address) != 0) return -1;
    return 0;
}

static int valid_path(const char *value) {
    size_t i, size = strlen(value);
    if (size < 2 || size >= sizeof(dots.path) || value[0] != '/' || value[size - 1] == '/')
        return 0;
    for (i = 0; i < size; ++i) {
        char ch = value[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '/' || ch == '-' || ch == '_' || ch == '.'))
            return 0;
    }
    return 1;
}

static int valid_server_name(const char *value) {
    size_t i, size = strlen(value);
    if (!size || size >= sizeof(dots.server_name)) return 0;
    for (i = 0; i < size; ++i) {
        char ch = value[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '.' || ch == '-')) return 0;
    }
    return 1;
}

int ankah_dots_path_option(const char *name) {
    return strcmp(name, "ca-file") == 0 || strcmp(name, "cert-file") == 0 ||
           strcmp(name, "key-file") == 0;
}

int ankah_dots_option(const char *name, const char *value) {
    if (strcmp(name, "server") == 0) {
        if (parse_server(value) != 0) return -1;
        dots.enabled = 1;
    } else if (strcmp(name, "server-name") == 0) {
        if (!valid_server_name(value)) return -1;
        strcpy(dots.server_name, value);
    } else if (strcmp(name, "path") == 0) {
        if (!valid_path(value)) return -1;
        strcpy(dots.path, value);
    } else if (strcmp(name, "ca-file") == 0) {
        return copy_value(dots.ca_file, sizeof(dots.ca_file), value);
    } else if (strcmp(name, "cert-file") == 0) {
        return copy_value(dots.cert_file, sizeof(dots.cert_file), value);
    } else if (strcmp(name, "key-file") == 0) {
        return copy_value(dots.key_file, sizeof(dots.key_file), value);
    } else if (strcmp(name, "cuid") == 0) {
        if (!ankah_dots_valid_cuid(value)) return -1;
        strcpy(dots.cuid, value);
    } else if (strcmp(name, "protected-network") == 0) {
        ankah_network network;
        if (ankah_parse_network(value, &network) != 0 ||
            copy_value(dots.protected_network, sizeof(dots.protected_network), value) != 0)
            return -1;
    } else if (strcmp(name, "protected-port") == 0) {
        return bounded_unsigned(value, 1, 65535, &dots.protected_port);
    } else if (strcmp(name, "threshold") == 0) {
        return bounded_unsigned(value, 1, ANKAH_DOTS_MAX_THRESHOLD, &dots.threshold);
    } else if (strcmp(name, "window-seconds") == 0) {
        return bounded_unsigned(value, 1, 3600, &dots.window_seconds);
    } else if (strcmp(name, "block-seconds") == 0) {
        return bounded_unsigned(value, 1, 86400, &dots.block_seconds);
    } else return -1;
    return 0;
}

int ankah_dots_finish(unsigned int trusted_proxies) {
    int any = dots.server_name[0] || dots.ca_file[0] || dots.cert_file[0] ||
              dots.key_file[0] || dots.cuid[0] || dots.protected_network[0];
    if (!dots.enabled) return any ? -1 : 0;
    if (!dots.path[0]) strcpy(dots.path, "/v1/restconf");
    if (!dots.protected_port) dots.protected_port = 80;
    if (!dots.threshold) dots.threshold = 10;
    if (!dots.window_seconds) dots.window_seconds = 5;
    if (!dots.block_seconds) dots.block_seconds = 45;
    if (!dots.server_name[0] || !dots.ca_file[0] || !dots.cert_file[0] ||
        !dots.key_file[0] || !dots.cuid[0] || !dots.protected_network[0] ||
        trusted_proxies == 0) return -1;
    return 0;
}

int ankah_dots_enabled(void) {
    return dots.enabled;
}

void ankah_dots_counters_get(ankah_dots_counters *out) {
    unsigned int i, active = 0;
    for (i = 0; i < DOTS_ACLS; ++i)
        if (dots.acls[i].state == ACL_ACTIVE || dots.acls[i].state == ACL_WITHDRAWING) ++active;
    *out = dots.counters;
    out->active = active;
    out->registered = dots.registered;
}

static void log_tls(const char *what, int result) {
    char message[160];
    mbedtls_strerror(result, message, sizeof(message));
    fprintf(stderr, "Ankah DOTS %s failed: %s\n", what, message);
}

static int read_pem(const char *path, unsigned char **out, size_t *size) {
    unsigned char *data, *replacement;
    size_t file_size;
    if (ankah_file_read(path, 1024U * 1024U, 1, &data, &file_size, NULL) != 0) return -1;
    replacement = realloc(data, file_size + 1);
    if (!replacement) { free(data); return -1; }
    replacement[file_size] = 0;
    *out = replacement;
    *size = file_size + 1;
    return 0;
}

static int load_tls(void) {
    unsigned char *pem = NULL;
    size_t size;
    int result;
    mbedtls_entropy_init(&dots.entropy);
    mbedtls_ctr_drbg_init(&dots.random);
    mbedtls_x509_crt_init(&dots.ca);
    mbedtls_x509_crt_init(&dots.certificate);
    mbedtls_pk_init(&dots.key);
    mbedtls_ssl_config_init(&dots.tls);
    dots.tls_ready = 1;
#if defined(MBEDTLS_PSA_CRYPTO_C)
    if (psa_crypto_init() != PSA_SUCCESS) {
        fprintf(stderr, "Ankah DOTS crypto initialization failed\n");
        return -1;
    }
#endif
    result = mbedtls_ctr_drbg_seed(&dots.random, mbedtls_entropy_func, &dots.entropy,
                                   (const unsigned char *)"ankah-dots", 10);
    if (result != 0) { log_tls("random seed", result); return -1; }
    if (read_pem(dots.ca_file, &pem, &size) != 0) {
        fprintf(stderr, "Ankah DOTS could not read %s\n", dots.ca_file);
        return -1;
    }
    result = mbedtls_x509_crt_parse(&dots.ca, pem, size);
    free(pem);
    if (result != 0) { log_tls("CA load", result); return -1; }
    if (read_pem(dots.cert_file, &pem, &size) != 0) {
        fprintf(stderr, "Ankah DOTS could not read %s\n", dots.cert_file);
        return -1;
    }
    result = mbedtls_x509_crt_parse(&dots.certificate, pem, size);
    free(pem);
    if (result != 0) { log_tls("client certificate load", result); return -1; }
    if (read_pem(dots.key_file, &pem, &size) != 0) {
        fprintf(stderr, "Ankah DOTS could not read %s\n", dots.key_file);
        return -1;
    }
    result = mbedtls_pk_parse_key(&dots.key, pem, size, NULL, 0,
                                  mbedtls_ctr_drbg_random, &dots.random);
    free(pem);
    if (result != 0) { log_tls("client key load", result); return -1; }
    result = mbedtls_pk_check_pair(&dots.certificate.pk, &dots.key,
                                   mbedtls_ctr_drbg_random, &dots.random);
    if (result != 0) { log_tls("client key check", result); return -1; }
    result = mbedtls_ssl_config_defaults(&dots.tls, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0) { log_tls("configuration", result); return -1; }
    mbedtls_ssl_conf_rng(&dots.tls, mbedtls_ctr_drbg_random, &dots.random);
    mbedtls_ssl_conf_min_tls_version(&dots.tls, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_authmode(&dots.tls, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&dots.tls, &dots.ca, NULL);
    result = mbedtls_ssl_conf_own_cert(&dots.tls, &dots.certificate, &dots.key);
    if (result != 0) { log_tls("client credential configuration", result); return -1; }
    return 0;
}

static void free_tls(void) {
    if (!dots.tls_ready) return;
    mbedtls_ssl_config_free(&dots.tls);
    mbedtls_pk_free(&dots.key);
    mbedtls_x509_crt_free(&dots.certificate);
    mbedtls_x509_crt_free(&dots.ca);
    mbedtls_ctr_drbg_free(&dots.random);
    mbedtls_entropy_free(&dots.entropy);
    dots.tls_ready = 0;
}

static dots_acl *find_acl(const char *ip) {
    unsigned int i;
    for (i = 0; i < DOTS_ACLS; ++i)
        if (dots.acls[i].state != ACL_FREE && strcmp(dots.acls[i].ip, ip) == 0)
            return &dots.acls[i];
    return NULL;
}

static dots_acl *find_acl_name(const char *name) {
    unsigned int i;
    for (i = 0; i < DOTS_ACLS; ++i)
        if (dots.acls[i].state != ACL_FREE && strcmp(dots.acls[i].name, name) == 0)
            return &dots.acls[i];
    return NULL;
}

static void start_next(void);

static int enqueue(int type, const char *name, const char *ip) {
    dots_op *op;
    if (dots.closing || dots.queue_count == DOTS_QUEUE) return -1;
    op = &dots.queue[(dots.queue_head + dots.queue_count) % DOTS_QUEUE];
    memset(op, 0, sizeof(*op));
    op->type = type;
    if (name) strcpy(op->name, name);
    if (ip) strcpy(op->ip, ip);
    ++dots.queue_count;
    start_next();
    return 0;
}

static void schedule_register(void) {
    if (dots.register_queued || dots.closing) return;
    if (enqueue(ANKAH_DOTS_OP_REGISTER, NULL, NULL) == 0) dots.register_queued = 1;
}

void ankah_dots_record(const char *ip, uint64_t now_ns) {
    dots_acl *slot = NULL;
    char name[ANKAH_DOTS_NAME_MAX];
    unsigned int i;
    if (!dots.enabled || dots.closing || !dots.loop) return;
    if (!ankah_dots_tracker_hit(&dots.tracker, ip, now_ns, dots.threshold,
                                (uint64_t)dots.window_seconds * SECOND_NS)) return;
    if (find_acl(ip)) return;
    ++dots.counters.escalations;
    if (!dots.registered || ankah_dots_acl_name(ip, name, sizeof(name)) != 0) {
        ++dots.counters.dropped;
        fprintf(stderr, "Ankah DOTS escalation for %s not sent (%s)\n", ip,
                dots.registered ? "invalid address" : "not registered");
        return;
    }
    for (i = 0; i < DOTS_ACLS && !slot; ++i)
        if (dots.acls[i].state == ACL_FREE) slot = &dots.acls[i];
    if (!slot) {
        ++dots.counters.dropped;
        fprintf(stderr, "Ankah DOTS escalation for %s not sent (table full)\n", ip);
        return;
    }
    slot->state = ACL_INSTALLING;
    strcpy(slot->ip, ip);
    strcpy(slot->name, name);
    fprintf(stderr, "Ankah DOTS escalation: %s reached %u challenged requests in %us\n",
            ip, dots.threshold, dots.window_seconds);
    if (enqueue(ANKAH_DOTS_OP_INSTALL, name, ip) != 0) {
        slot->state = ACL_FREE;
        ++dots.counters.dropped;
    }
}

static void on_sweep(uv_timer_t *timer) {
    uint64_t now = uv_hrtime();
    unsigned int i;
    (void)timer;
    if (!dots.registered && !dots.register_queued && now >= dots.register_retry_ns)
        schedule_register();
    for (i = 0; i < DOTS_ACLS; ++i) {
        dots_acl *acl = &dots.acls[i];
        if (acl->state != ACL_ACTIVE || now < acl->expires_ns) continue;
        if (enqueue(ANKAH_DOTS_OP_WITHDRAW, acl->name, acl->ip) == 0)
            acl->state = ACL_WITHDRAWING;
        else acl->expires_ns = now + SECOND_NS;
    }
}

static int build_request(dots_conn *conn) {
    char body[2048], target[512];
    const char *method = "GET";
    int body_size = 0, written;
    const dots_op *op = &conn->op;
    const char *base = "/data/ietf-dots-data-channel:dots-data/dots-client=";
    switch (op->type) {
    case ANKAH_DOTS_OP_REGISTER:
        method = "PUT";
        written = snprintf(target, sizeof(target), "%s%s%s", dots.path, base, dots.cuid);
        body_size = ankah_dots_client_body(dots.cuid, body, sizeof(body));
        break;
    case ANKAH_DOTS_OP_LIST:
        written = snprintf(target, sizeof(target), "%s%s%s/acls", dots.path, base, dots.cuid);
        break;
    case ANKAH_DOTS_OP_INSTALL:
        method = "PUT";
        written = snprintf(target, sizeof(target), "%s%s%s/acls/acl=%s",
                           dots.path, base, dots.cuid, op->name);
        body_size = ankah_dots_acl_body(op->name, op->ip, dots.protected_network,
                                        dots.protected_port, body, sizeof(body));
        break;
    case ANKAH_DOTS_OP_WITHDRAW:
        method = "DELETE";
        written = snprintf(target, sizeof(target), "%s%s%s/acls/acl=%s",
                           dots.path, base, dots.cuid, op->name);
        break;
    default:
        return -1;
    }
    if (written < 0 || (size_t)written >= sizeof(target) || body_size < 0) return -1;
    written = snprintf(conn->request, sizeof(conn->request),
                       "%s %s HTTP/1.1\r\n"
                       "Host: %s:%d\r\n"
                       "Accept: application/yang-data+json\r\n"
                       "Content-Type: application/yang-data+json\r\n"
                       "Content-Length: %d\r\n"
                       "Connection: close\r\n"
                       "\r\n"
                       "%s",
                       method, target, dots.server_name, dots.server_port,
                       body_size, body_size ? body : "");
    if (written < 0 || (size_t)written >= sizeof(conn->request)) return -1;
    conn->request_size = (size_t)written;
    return 0;
}

static void apply_result(const dots_op *op, int status, const char *body, size_t body_size) {
    int ok;
    dots_acl *acl;
    uint64_t now = uv_hrtime();
    switch (op->type) {
    case ANKAH_DOTS_OP_REGISTER:
        dots.register_queued = 0;
        ok = status == 201 || status == 204;
        if (ok) {
            dots.registered = 1;
            dots.register_backoff_ms = 0;
            fprintf(stderr, "Ankah DOTS client %s registered\n", dots.cuid);
            (void)enqueue(ANKAH_DOTS_OP_LIST, NULL, NULL);
        } else {
            dots.register_backoff_ms = dots.register_backoff_ms
                ? dots.register_backoff_ms * 2 : 1000U;
            if (dots.register_backoff_ms > DOTS_REGISTER_BACKOFF_MAX_MS)
                dots.register_backoff_ms = DOTS_REGISTER_BACKOFF_MAX_MS;
            dots.register_retry_ns = now + (uint64_t)dots.register_backoff_ms * 1000000U;
        }
        break;
    case ANKAH_DOTS_OP_LIST: {
        /* Withdraw ACLs this client installed before a restart. */
        static char names[DOTS_QUEUE / 2][ANKAH_DOTS_NAME_MAX];
        size_t count, i;
        ok = status == 200;
        if (!ok) break;
        count = ankah_dots_scan_names(body, body_size, "ankah-", names, DOTS_QUEUE / 2);
        for (i = 0; i < count; ++i) {
            if (find_acl_name(names[i])) continue;
            fprintf(stderr, "Ankah DOTS withdrawing stale ACL %s\n", names[i]);
            (void)enqueue(ANKAH_DOTS_OP_WITHDRAW, names[i], NULL);
        }
        break;
    }
    case ANKAH_DOTS_OP_INSTALL:
        ok = status == 201 || status == 204;
        acl = find_acl_name(op->name);
        if (acl && ok) {
            acl->state = ACL_ACTIVE;
            acl->expires_ns = now + (uint64_t)dots.block_seconds * SECOND_NS;
            fprintf(stderr, "Ankah DOTS ACL %s installed for %us\n", op->name,
                    dots.block_seconds);
        } else if (acl) {
            acl->state = ACL_FREE;
        }
        break;
    case ANKAH_DOTS_OP_WITHDRAW:
        /* 404 means the server no longer holds it, which is the goal. */
        ok = status == 204 || status == 200 || status == 404;
        acl = find_acl_name(op->name);
        if (acl && ok) {
            acl->state = ACL_FREE;
            fprintf(stderr, "Ankah DOTS ACL %s withdrawn\n", op->name);
        } else if (acl) {
            acl->state = ACL_ACTIVE;
            acl->expires_ns = now + DOTS_RETRY_NS;
        }
        break;
    default:
        return;
    }
    if (ok) ++dots.counters.ok[op->type];
    else {
        ++dots.counters.failed[op->type];
        fprintf(stderr, "Ankah DOTS %s %s failed (status %d)\n",
                operation_names[op->type], op->name[0] ? op->name : dots.cuid, status);
        if (status == 404 && op->type == ANKAH_DOTS_OP_INSTALL) {
            /* The server lost our registration. */
            dots.registered = 0;
        }
    }
}

static void on_conn_closed(uv_handle_t *handle) {
    dots_conn *conn = handle->data;
    if (--conn->handles) return;
    if (conn->ssl_ready) mbedtls_ssl_free(&conn->ssl);
    free(conn->cipher);
    free(conn);
    if (dots.current == conn) dots.current = NULL;
    if (dots.closing) {
        if (!dots.sweep_initialized) free_tls();
        return;
    }
    start_next();
}

static void finish(dots_conn *conn, int transport_ok) {
    int status = -1;
    const char *body = "";
    size_t body_size = 0;
    if (conn->finished) return;
    conn->finished = 1;
    if (transport_ok || conn->response_size) {
        const char *end;
        status = ankah_dots_status(conn->response, conn->response_size);
        conn->response[conn->response_size < DOTS_RESPONSE_MAX
                       ? conn->response_size : DOTS_RESPONSE_MAX - 1] = 0;
        end = strstr(conn->response, "\r\n\r\n");
        if (end) {
            body = end + 4;
            body_size = conn->response_size - (size_t)(body - conn->response);
        }
    }
    apply_result(&conn->op, status, body, body_size);
    uv_timer_stop(&conn->timer);
    uv_read_stop((uv_stream_t *)&conn->tcp);
    uv_close((uv_handle_t *)&conn->tcp, on_conn_closed);
    uv_close((uv_handle_t *)&conn->timer, on_conn_closed);
}

static void on_write(uv_write_t *request, int status) {
    dots_write *write = request->data;
    dots_conn *conn = write->conn;
    free(write->buffer.base);
    free(write);
    --conn->writes_pending;
    if (status < 0) finish(conn, 0);
}

static int tls_send(void *context, const unsigned char *data, size_t size) {
    dots_conn *conn = context;
    dots_write *write;
    uv_buf_t buffers[1];
    if (conn->finished) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if (conn->writes_pending >= 16) return MBEDTLS_ERR_SSL_WANT_WRITE;
    write = calloc(1, sizeof(*write));
    if (!write) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    write->buffer.base = malloc(size ? size : 1);
    if (!write->buffer.base) { free(write); return MBEDTLS_ERR_SSL_ALLOC_FAILED; }
    memcpy(write->buffer.base, data, size);
    write->buffer.len = (unsigned int)size;
    write->conn = conn;
    write->request.data = write;
    buffers[0] = write->buffer;
    if (uv_write(&write->request, (uv_stream_t *)&conn->tcp, buffers, 1, on_write) != 0) {
        free(write->buffer.base);
        free(write);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    ++conn->writes_pending;
    return (int)size;
}

static int tls_receive(void *context, unsigned char *out, size_t size) {
    dots_conn *conn = context;
    size_t available = conn->cipher_size - conn->cipher_offset;
    if (!available) return conn->eof ? 0 : MBEDTLS_ERR_SSL_WANT_READ;
    if (size > available) size = available;
    memcpy(out, conn->cipher + conn->cipher_offset, size);
    conn->cipher_offset += size;
    if (conn->cipher_offset == conn->cipher_size) {
        free(conn->cipher);
        conn->cipher = NULL;
        conn->cipher_size = conn->cipher_offset = 0;
    }
    return (int)size;
}

static void drive(dots_conn *conn) {
    int result;
    if (conn->finished) return;
    if (!conn->handshaken) {
        result = mbedtls_ssl_handshake(&conn->ssl);
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) return;
        if (result != 0) {
            log_tls("handshake", result);
            finish(conn, 0);
            return;
        }
        conn->handshaken = 1;
    }
    while (conn->request_sent < conn->request_size) {
        result = mbedtls_ssl_write(&conn->ssl,
                                   (const unsigned char *)conn->request + conn->request_sent,
                                   conn->request_size - conn->request_sent);
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) return;
        if (result <= 0) { finish(conn, 0); return; }
        conn->request_sent += (size_t)result;
    }
    for (;;) {
        size_t room = DOTS_RESPONSE_MAX - 1 - conn->response_size;
        if (!room) { finish(conn, 1); return; }
        result = mbedtls_ssl_read(&conn->ssl,
                                  (unsigned char *)conn->response + conn->response_size, room);
        if (result > 0) { conn->response_size += (size_t)result; continue; }
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (conn->eof) finish(conn, conn->response_size != 0);
            return;
        }
#if defined(MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
        if (result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
#endif
        /* Close notify, end of stream, or an error after the response. */
        finish(conn, result == 0 || result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
                     conn->response_size != 0);
        return;
    }
}

static void on_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buffer) {
    (void)handle;
    (void)suggested;
    buffer->base = malloc(16384);
    buffer->len = buffer->base ? 16384 : 0;
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buffer) {
    dots_conn *conn = stream->data;
    if (nread > 0) {
        size_t available = conn->cipher_size - conn->cipher_offset;
        unsigned char *replacement;
        if ((size_t)nread > DOTS_CIPHER_MAX - available ||
            !(replacement = malloc(available + (size_t)nread))) {
            free(buffer->base);
            finish(conn, 0);
            return;
        }
        if (available) memcpy(replacement, conn->cipher + conn->cipher_offset, available);
        memcpy(replacement + available, buffer->base, (size_t)nread);
        free(conn->cipher);
        conn->cipher = replacement;
        conn->cipher_offset = 0;
        conn->cipher_size = available + (size_t)nread;
    } else if (nread < 0) {
        conn->eof = 1;
    }
    free(buffer->base);
    drive(conn);
}

static void on_connect(uv_connect_t *request, int status) {
    dots_conn *conn = request->data;
    int result;
    if (conn->finished) return;
    if (status < 0) {
        fprintf(stderr, "Ankah DOTS connect to %s:%d failed: %s\n",
                dots.server_ip, dots.server_port, uv_strerror(status));
        finish(conn, 0);
        return;
    }
    mbedtls_ssl_init(&conn->ssl);
    conn->ssl_ready = 1;
    if ((result = mbedtls_ssl_setup(&conn->ssl, &dots.tls)) != 0 ||
        (result = mbedtls_ssl_set_hostname(&conn->ssl, dots.server_name)) != 0) {
        log_tls("session setup", result);
        finish(conn, 0);
        return;
    }
    mbedtls_ssl_set_bio(&conn->ssl, conn, tls_send, tls_receive, NULL);
    if (uv_read_start((uv_stream_t *)&conn->tcp, on_alloc, on_read) != 0) {
        finish(conn, 0);
        return;
    }
    drive(conn);
}

static void on_timeout(uv_timer_t *timer) {
    dots_conn *conn = timer->data;
    fprintf(stderr, "Ankah DOTS %s timed out\n", operation_names[conn->op.type]);
    finish(conn, 0);
}

static void start_next(void) {
    dots_conn *conn;
    if (dots.current || !dots.queue_count || dots.closing) return;
    conn = calloc(1, sizeof(*conn));
    if (!conn) return;
    conn->op = dots.queue[dots.queue_head];
    dots.queue_head = (dots.queue_head + 1) % DOTS_QUEUE;
    --dots.queue_count;
    if (build_request(conn) != 0) {
        apply_result(&conn->op, -1, "", 0);
        free(conn);
        start_next();
        return;
    }
    conn->tcp.data = conn;
    conn->timer.data = conn;
    conn->connect.data = conn;
    if (uv_tcp_init(dots.loop, &conn->tcp) != 0) {
        apply_result(&conn->op, -1, "", 0);
        free(conn);
        return;
    }
    conn->handles = 1;
    if (uv_timer_init(dots.loop, &conn->timer) != 0) {
        conn->finished = 1;
        apply_result(&conn->op, -1, "", 0);
        uv_close((uv_handle_t *)&conn->tcp, on_conn_closed);
        return;
    }
    conn->handles = 2;
    dots.current = conn;
    uv_timer_start(&conn->timer, on_timeout, DOTS_TIMEOUT_MS, 0);
    if (uv_tcp_connect(&conn->connect, &conn->tcp,
                       (const struct sockaddr *)&dots.address, on_connect) != 0)
        finish(conn, 0);
}

int ankah_dots_start(uv_loop_t *loop) {
    if (!dots.enabled) return 0;
    if (load_tls() != 0) return -1;
    dots.loop = loop;
    if (uv_timer_init(loop, &dots.sweep) != 0) return -1;
    dots.sweep_initialized = 1;
    if (uv_timer_start(&dots.sweep, on_sweep, DOTS_SWEEP_MS, DOTS_SWEEP_MS) != 0) return -1;
    uv_unref((uv_handle_t *)&dots.sweep);
    fprintf(stderr, "Ankah DOTS client %s -> %s:%d (%s), protecting %s tcp/%u; "
                    "threshold %u in %us, block %us\n",
            dots.cuid, dots.server_ip, dots.server_port, dots.server_name,
            dots.protected_network, dots.protected_port, dots.threshold,
            dots.window_seconds, dots.block_seconds);
    schedule_register();
    return 0;
}

static void on_sweep_closed(uv_handle_t *handle) {
    (void)handle;
    if (!dots.current) free_tls();
}


void ankah_dots_close(void) {
    if (!dots.enabled || dots.closing) return;
    dots.closing = 1;
    dots.queue_count = 0;
    if (dots.current) finish(dots.current, 0);
    if (dots.sweep_initialized) {
        dots.sweep_initialized = 0;
        uv_close((uv_handle_t *)&dots.sweep, on_sweep_closed);
    }
}
