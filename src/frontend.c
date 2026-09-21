#include "ankah/frontend.h"
#include "ankah/files.h"
#include "header_names.h"
#include "ankah/http.h"
#include "ankah/stats.h"

#include <llhttp.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <nghttp2/nghttp2.h>

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRONT_MAX_CONNECTIONS ANKAH_FRONTEND_MAX_CONNECTIONS
#define FRONT_MAX_CIPHER_INPUT (256U * 1024U)
#define FRONT_MAX_PLAIN_OUTPUT (2U * 1024U * 1024U)
#define FRONT_MAX_H1_HEADER ANKAH_HEADER_LIMIT
#define H2_MAX_STREAMS 32
#define H2_MAX_BODY (16U * 1024U * 1024U)
#define H2_MAX_BODY_TOTAL (64U * 1024U * 1024U)
#define H2_MAX_RESPONSE_QUEUE (2U * 1024U * 1024U)

typedef struct tls_credentials tls_credentials;
typedef struct front_connection front_connection;
typedef struct h2_stream h2_stream;

typedef struct buffer_chunk buffer_chunk;
struct buffer_chunk {
    buffer_chunk *next;
    size_t size;
    size_t offset;
    unsigned char data[];
};

struct tls_credentials {
    mbedtls_x509_crt certificate;
    mbedtls_pk_context key;
    mbedtls_ssl_config config;
    unsigned int references;
    int retired;
};

typedef struct {
    uv_write_t request;
    uv_buf_t buffer;
    front_connection *front;
} cipher_write;

typedef struct {
    uv_write_t request;
    uv_buf_t buffer;
    front_connection *front;
} bridge_write;

struct h2_stream {
    h2_stream *next;
    front_connection *front;
    int32_t id;
    ankah_request request;
    char authority[ANKAH_MAX_VALUE];
    char scheme[16];
    int saw_method;
    int saw_path;
    int saw_authority;
    int regular_headers;
    int invalid;
    int dispatched;
    int closed_by_h2;
    unsigned char *body;
    size_t body_size;
    size_t body_capacity;
    uv_tcp_t core;
    uv_connect_t core_connect;
    int core_initialized;
    int core_connected;
    int core_read_stopped;
    llhttp_t response_parser;
    llhttp_settings_t response_settings;
    ankah_header response_headers[ANKAH_MAX_HEADERS];
    unsigned int response_count;
    unsigned int response_initial_count;
    int response_stage;
    int response_status;
    int response_final;
    int response_complete;
    int response_has_body;
    buffer_chunk *response_first;
    buffer_chunk *response_last;
    size_t response_queued;
    int data_submitted;
};

struct front_connection {
    uv_tcp_t client;
    uv_tcp_t bridge;
    uv_connect_t bridge_connect;
    uv_timer_t timer;
    mbedtls_ssl_context ssl;
    tls_credentials *credentials;
    unsigned int handles;
    unsigned int cipher_pending;
    unsigned int bridge_pending;
    int bridge_initialized;
    int bridge_connected;
    int timer_initialized;
    int handshake_complete;
    int protocol_h2;
    int closing;
    int close_notify_started;
    int close_notify_sent;
    int driving;
    int drive_again;
    char peer_ip[64];
    unsigned char *cipher_input;
    size_t cipher_size;
    size_t cipher_offset;
    buffer_chunk *plain_first;
    buffer_chunk *plain_last;
    size_t plain_queued;
    unsigned char h1_header[FRONT_MAX_H1_HEADER];
    size_t h1_header_size;
    int h1_header_sent;
    nghttp2_session *h2;
    h2_stream *streams;
    size_t h2_body_total;
};

typedef struct {
    ankah_frontend_options options;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    tls_credentials *active;
    unsigned int connections;
#ifndef _WIN32
    uv_signal_t reload_signal;
    int reload_signal_initialized;
#else
    uv_fs_event_t certificate_watch;
    uv_fs_event_t key_watch;
    uv_timer_t reload_timer;
    int certificate_watch_initialized;
    int key_watch_initialized;
    int reload_timer_initialized;
#endif
} frontend_configuration;

static frontend_configuration frontend;

static void drive_tls(front_connection *front);
static void close_front(front_connection *front);
static void h2_flush(front_connection *front);
static void h2_dispatch(h2_stream *stream);
static void on_timeout(uv_timer_t *timer);
static void on_h2_core_read(uv_stream_t *handle, ssize_t count, const uv_buf_t *buffer);

static int same_ascii_part(const char *left, size_t left_size,
                           const char *right, size_t right_size) {
    size_t i;
    if (left_size != right_size) return 0;
    for (i = 0; i < left_size; ++i) {
        unsigned char a = (unsigned char)left[i];
        unsigned char b = (unsigned char)right[i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
        if (a != b) return 0;
    }
    return 1;
}

static size_t find_header_end(const unsigned char *data, size_t size) {
    size_t i;
    for (i = 3; i < size; ++i)
        if (data[i - 3] == '\r' && data[i - 2] == '\n' &&
            data[i - 1] == '\r' && data[i] == '\n') return i + 1;
    return 0;
}

static void log_tls_error(const char *action, int error) {
    char text[160];
    mbedtls_strerror(error, text, sizeof(text));
    fprintf(stderr, "Ankah TLS %s failed: %s\n", action, text);
}

static void credentials_free(tls_credentials *credentials) {
    if (!credentials) return;
    mbedtls_ssl_config_free(&credentials->config);
    mbedtls_pk_free(&credentials->key);
    mbedtls_x509_crt_free(&credentials->certificate);
    free(credentials);
}

static void credentials_release(tls_credentials *credentials) {
    if (!credentials) return;
    if (credentials->references) --credentials->references;
    if (credentials->retired && !credentials->references) credentials_free(credentials);
}

static int read_pem(const char *path, unsigned char **out, size_t *size) {
    size_t file_size;
    unsigned char *data, *replacement;
    if (ankah_file_read(path, 8U * 1024U * 1024U, 1,
                        &data, &file_size, NULL) != 0) return -1;
    if (file_size == SIZE_MAX) { free(data); return -1; }
    replacement = realloc(data, file_size + 1);
    if (!replacement) { free(data); return -1; }
    data = replacement;
    data[file_size] = 0;
    *out = data;
    *size = file_size + 1;
    return 0;
}

static tls_credentials *credentials_load(void) {
    static const char *protocols[] = {"h2", "http/1.1", NULL};
    tls_credentials *credentials = calloc(1, sizeof(*credentials));
    unsigned char *certificate = NULL, *key = NULL;
    size_t certificate_size = 0, key_size = 0;
    int result;
    if (!credentials) return NULL;
    mbedtls_x509_crt_init(&credentials->certificate);
    mbedtls_pk_init(&credentials->key);
    mbedtls_ssl_config_init(&credentials->config);
    if (read_pem(frontend.options.certificate_path, &certificate, &certificate_size) != 0 ||
        read_pem(frontend.options.key_path, &key, &key_size) != 0) goto failed;
    result = mbedtls_x509_crt_parse(&credentials->certificate, certificate, certificate_size);
    if (result != 0) { log_tls_error("certificate load", result); goto failed; }
    result = mbedtls_pk_parse_key(&credentials->key, key, key_size, NULL, 0,
                                  mbedtls_ctr_drbg_random, &frontend.random);
    if (result != 0) { log_tls_error("key load", result); goto failed; }
    result = mbedtls_pk_check_pair(&credentials->certificate.pk, &credentials->key,
                                   mbedtls_ctr_drbg_random, &frontend.random);
    if (result != 0) { log_tls_error("certificate check", result); goto failed; }
    result = mbedtls_ssl_config_defaults(&credentials->config,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0) { log_tls_error("configuration", result); goto failed; }
    mbedtls_ssl_conf_rng(&credentials->config, mbedtls_ctr_drbg_random, &frontend.random);
    mbedtls_ssl_conf_min_tls_version(&credentials->config, MBEDTLS_SSL_VERSION_TLS1_2);
    result = mbedtls_ssl_conf_alpn_protocols(&credentials->config, protocols);
    if (result != 0) { log_tls_error("ALPN configuration", result); goto failed; }
    result = mbedtls_ssl_conf_own_cert(&credentials->config,
                                       &credentials->certificate, &credentials->key);
    if (result != 0) { log_tls_error("credential configuration", result); goto failed; }
    free(certificate);
    free(key);
    return credentials;
failed:
    free(certificate);
    free(key);
    credentials_free(credentials);
    return NULL;
}

static int reload_credentials(void) {
    tls_credentials *replacement = credentials_load();
    tls_credentials *previous;
    if (!replacement) {
        fprintf(stderr, "Ankah kept the current TLS credentials\n");
        return -1;
    }
    previous = frontend.active;
    frontend.active = replacement;
    if (previous) {
        previous->retired = 1;
        if (!previous->references) credentials_free(previous);
    }
    fprintf(stderr, "Ankah reloaded TLS credentials\n");
    return 0;
}

#ifndef _WIN32
static void on_reload_signal(uv_signal_t *signal, int number) {
    (void)signal;
    (void)number;
    reload_credentials();
}
#else
static void on_reload_timer(uv_timer_t *timer) {
    (void)timer;
    reload_credentials();
}

static void on_credential_change(uv_fs_event_t *watcher, const char *filename,
                                 int events, int status) {
    (void)watcher;
    (void)filename;
    (void)events;
    if (status < 0) return;
    uv_timer_start(&frontend.reload_timer, on_reload_timer, 500, 0);
}

static int parent_path(const char *path, char *out, size_t capacity) {
    const char *slash = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    const char *last = slash;
    size_t length;
    if (backslash && (!last || backslash > last)) last = backslash;
    if (!last) {
        if (capacity < 2) return -1;
        strcpy(out, ".");
        return 0;
    }
    length = (size_t)(last - path);
    if (!length) length = 1;
    if (length >= capacity) return -1;
    memcpy(out, path, length);
    out[length] = 0;
    return 0;
}
#endif

static buffer_chunk *chunk_new(const void *data, size_t size) {
    buffer_chunk *chunk = malloc(sizeof(*chunk) + (size ? size : 1));
    if (!chunk) return NULL;
    chunk->next = NULL;
    chunk->size = size;
    chunk->offset = 0;
    if (size) memcpy(chunk->data, data, size);
    return chunk;
}

static int queue_plain(front_connection *front, const void *data, size_t size) {
    buffer_chunk *chunk;
    if (size > FRONT_MAX_PLAIN_OUTPUT - front->plain_queued) return -1;
    chunk = chunk_new(data, size);
    if (!chunk) return -1;
    if (front->plain_last) front->plain_last->next = chunk;
    else front->plain_first = chunk;
    front->plain_last = chunk;
    front->plain_queued += size;
    return 0;
}

static void free_chunks(buffer_chunk *chunk) {
    while (chunk) {
        buffer_chunk *next = chunk->next;
        free(chunk);
        chunk = next;
    }
}

static void front_unref(front_connection *front) {
    if (--front->handles) return;
    if (front->h2) nghttp2_session_del(front->h2);
    while (front->streams) {
        h2_stream *next = front->streams->next;
        free(front->streams->body);
        free_chunks(front->streams->response_first);
        free(front->streams);
        front->streams = next;
    }
    free(front->cipher_input);
    free_chunks(front->plain_first);
    mbedtls_ssl_free(&front->ssl);
    credentials_release(front->credentials);
    --frontend.connections;
    free(front);
}

static void stream_maybe_free(h2_stream *stream) {
    front_connection *front = stream->front;
    h2_stream **item;
    if (!stream->closed_by_h2 || stream->core_initialized || front->closing) return;
    for (item = &front->streams; *item; item = &(*item)->next) {
        if (*item == stream) {
            *item = stream->next;
            free(stream->body);
            free_chunks(stream->response_first);
            free(stream);
            return;
        }
    }
}

static void on_front_handle_closed(uv_handle_t *handle) {
    front_unref((front_connection *)handle->data);
}

static void on_discard_closed(uv_handle_t *handle) {
    free(handle);
}

static void on_stream_core_closed(uv_handle_t *handle) {
    h2_stream *stream = (h2_stream *)handle->data;
    front_connection *front = stream->front;
    stream->core_initialized = 0;
    stream_maybe_free(stream);
    front_unref(front);
}

static void close_stream_core(h2_stream *stream) {
    if (stream->core_initialized && !uv_is_closing((uv_handle_t *)&stream->core))
        uv_close((uv_handle_t *)&stream->core, on_stream_core_closed);
}

static void close_front(front_connection *front) {
    h2_stream *stream;
    if (front->closing) return;
    front->closing = 1;
    uv_read_stop((uv_stream_t *)&front->client);
    if (front->bridge_initialized) uv_read_stop((uv_stream_t *)&front->bridge);
    for (stream = front->streams; stream; stream = stream->next) close_stream_core(stream);
    if (!uv_is_closing((uv_handle_t *)&front->client))
        uv_close((uv_handle_t *)&front->client, on_front_handle_closed);
    if (front->bridge_initialized && !uv_is_closing((uv_handle_t *)&front->bridge))
        uv_close((uv_handle_t *)&front->bridge, on_front_handle_closed);
    if (front->timer_initialized && !uv_is_closing((uv_handle_t *)&front->timer))
        uv_close((uv_handle_t *)&front->timer, on_front_handle_closed);
}

static void refresh_timeout(front_connection *front) {
    uv_timer_start(&front->timer, on_timeout,
                   front->handshake_complete && front->protocol_h2 ? 120000 :
                   front->handshake_complete ? 30000 : 10000, 0);
}

static void allocate_read(uv_handle_t *handle, size_t suggested, uv_buf_t *buffer) {
    (void)handle;
    (void)suggested;
    buffer->base = malloc(16384);
    buffer->len = buffer->base ? 16384 : 0;
}

static int tls_receive(void *context, unsigned char *out, size_t size) {
    front_connection *front = context;
    size_t available = front->cipher_size - front->cipher_offset;
    if (!available) return MBEDTLS_ERR_SSL_WANT_READ;
    if (size > available) size = available;
    memcpy(out, front->cipher_input + front->cipher_offset, size);
    front->cipher_offset += size;
    if (front->cipher_offset == front->cipher_size) {
        free(front->cipher_input);
        front->cipher_input = NULL;
        front->cipher_size = 0;
        front->cipher_offset = 0;
    }
    return (int)size;
}

static void on_cipher_write(uv_write_t *request, int status) {
    cipher_write *write = request->data;
    front_connection *front = write->front;
    free(write->buffer.base);
    free(write);
    --front->cipher_pending;
    if (status < 0) close_front(front);
    else if (!front->closing) drive_tls(front);
}

static int tls_send(void *context, const unsigned char *data, size_t size) {
    front_connection *front = context;
    cipher_write *write;
    uv_buf_t buffers[1];
    int result;
    if (front->closing) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if (front->cipher_pending >= 16) return MBEDTLS_ERR_SSL_WANT_WRITE;
    write = calloc(1, sizeof(*write));
    if (!write) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    write->buffer.base = malloc(size ? size : 1);
    if (!write->buffer.base) { free(write); return MBEDTLS_ERR_SSL_ALLOC_FAILED; }
    memcpy(write->buffer.base, data, size);
    write->buffer.len = (unsigned int)size;
    write->front = front;
    write->request.data = write;
    ++front->cipher_pending;
    buffers[0] = write->buffer;
    result = uv_write(&write->request, (uv_stream_t *)&front->client,
                      buffers, 1, on_cipher_write);
    if (result < 0) {
        --front->cipher_pending;
        free(write->buffer.base);
        free(write);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return (int)size;
}

static int append_cipher(front_connection *front, const void *data, size_t size) {
    size_t available = front->cipher_size - front->cipher_offset;
    unsigned char *replacement;
    if (size > FRONT_MAX_CIPHER_INPUT - available) return -1;
    replacement = malloc(available + size);
    if (!replacement) return -1;
    if (available) memcpy(replacement, front->cipher_input + front->cipher_offset, available);
    memcpy(replacement + available, data, size);
    free(front->cipher_input);
    front->cipher_input = replacement;
    front->cipher_offset = 0;
    front->cipher_size = available + size;
    return 0;
}

static void on_bridge_write(uv_write_t *request, int status) {
    bridge_write *write = request->data;
    front_connection *front = write->front;
    free(write->buffer.base);
    free(write);
    --front->bridge_pending;
    if (status < 0) close_front(front);
    else if (!front->closing) drive_tls(front);
}

static int write_bridge(front_connection *front, const void *data, size_t size) {
    bridge_write *write;
    uv_buf_t buffers[1];
    int result;
    if (!size) return 0;
    write = calloc(1, sizeof(*write));
    if (!write) return -1;
    write->buffer.base = malloc(size);
    if (!write->buffer.base) { free(write); return -1; }
    memcpy(write->buffer.base, data, size);
    write->buffer.len = (unsigned int)size;
    write->front = front;
    write->request.data = write;
    ++front->bridge_pending;
    buffers[0] = write->buffer;
    result = uv_write(&write->request, (uv_stream_t *)&front->bridge,
                      buffers, 1, on_bridge_write);
    if (result < 0) {
        --front->bridge_pending;
        free(write->buffer.base);
        free(write);
        return -1;
    }
    return 0;
}

static int send_h1_header(front_connection *front) {
    size_t end = find_header_end(front->h1_header, front->h1_header_size);
    char metadata[320];
    unsigned char *request;
    size_t metadata_size, output_size;
    int length;
    if (!end) return front->h1_header_size == sizeof(front->h1_header) ? -1 : 0;
    length = snprintf(metadata, sizeof(metadata),
                      "X-Ankah-Internal-Key: %s\r\nX-Ankah-Internal-Peer: %s\r\n",
                      frontend.options.internal_key,
                      front->peer_ip);
    if (length < 0 || (size_t)length >= sizeof(metadata)) return -1;
    metadata_size = (size_t)length;
    output_size = front->h1_header_size + metadata_size;
    request = malloc(output_size);
    if (!request) return -1;
    memcpy(request, front->h1_header, end - 2);
    memcpy(request + end - 2, metadata, metadata_size);
    memcpy(request + end - 2 + metadata_size,
           front->h1_header + end - 2, front->h1_header_size - end + 2);
    if (write_bridge(front, request, output_size) != 0) {
        free(request);
        return -1;
    }
    free(request);
    front->h1_header_sent = 1;
    front->h1_header_size = 0;
    return 1;
}

static int forward_h1_plain(front_connection *front,
                            const unsigned char *data, size_t size) {
    if (front->h1_header_sent) return write_bridge(front, data, size);
    if (size > sizeof(front->h1_header) - front->h1_header_size) return -1;
    memcpy(front->h1_header + front->h1_header_size, data, size);
    front->h1_header_size += size;
    return send_h1_header(front) < 0 ? -1 : 0;
}

static void on_bridge_read(uv_stream_t *handle, ssize_t count, const uv_buf_t *buffer) {
    front_connection *front = handle->data;
    if (count > 0 && !front->closing) {
        refresh_timeout(front);
        if (queue_plain(front, buffer->base, (size_t)count) != 0) close_front(front);
        else {
            if (front->plain_queued >= FRONT_MAX_PLAIN_OUTPUT - 16384U)
                uv_read_stop(handle);
            drive_tls(front);
        }
    } else if (count < 0 && !front->closing) {
        front->close_notify_started = 1;
        drive_tls(front);
    }
    free(buffer->base);
}

static void on_bridge_connected(uv_connect_t *request, int status) {
    front_connection *front = request->data;
    if (status < 0 || front->closing) { close_front(front); return; }
    front->bridge_connected = 1;
    if (uv_read_start((uv_stream_t *)&front->bridge, allocate_read, on_bridge_read) != 0)
        close_front(front);
    else drive_tls(front);
}

static int connect_h1_bridge(front_connection *front) {
    struct sockaddr_in address;
    if (uv_ip4_addr("127.0.0.1", frontend.options.internal_port, &address) != 0 ||
        uv_tcp_init(frontend.options.loop, &front->bridge) != 0) return -1;
    front->bridge_initialized = 1;
    ++front->handles;
    front->bridge.data = front;
    front->bridge_connect.data = front;
    return uv_tcp_connect(&front->bridge_connect, &front->bridge,
                          (const struct sockaddr *)&address, on_bridge_connected);
}

static h2_stream *find_stream(front_connection *front, int32_t id) {
    h2_stream *stream;
    for (stream = front->streams; stream; stream = stream->next)
        if (stream->id == id) return stream;
    return NULL;
}

static int append_text(char *out, size_t capacity, const uint8_t *data, size_t size) {
    size_t used = strlen(out);
    if (size >= capacity || used >= capacity - size) return -1;
    memcpy(out + used, data, size);
    out[used + size] = 0;
    return 0;
}

static int h2_on_begin_headers(nghttp2_session *session,
                               const nghttp2_frame *frame, void *user_data) {
    front_connection *front = user_data;
    h2_stream *stream;
    (void)session;
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    stream = calloc(1, sizeof(*stream));
    if (!stream) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    stream->front = front;
    stream->id = frame->hd.stream_id;
    stream->next = front->streams;
    front->streams = stream;
    nghttp2_session_set_stream_user_data(front->h2, stream->id, stream);
    return 0;
}

static int h2_on_header(nghttp2_session *session, const nghttp2_frame *frame,
                        const uint8_t *name, size_t name_size,
                        const uint8_t *value, size_t value_size,
                        uint8_t flags, void *user_data) {
    front_connection *front = user_data;
    h2_stream *stream = find_stream(front, frame->hd.stream_id);
    ankah_header *header;
    unsigned char kind;
    (void)session;
    (void)flags;
    if (!stream || stream->invalid || frame->hd.type != NGHTTP2_HEADERS) return 0;
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    kind = ankah_header_name_kind((const char *)name, name_size);
    if (name_size && name[0] == ':') {
        if (stream->regular_headers) { stream->invalid = 1; return 0; }
        if (kind == ANKAH_HEADER_PSEUDO_METHOD) {
            if (stream->saw_method || value_size >= sizeof(stream->request.method)) stream->invalid = 1;
            else {
                memcpy(stream->request.method, value, value_size);
                stream->request.method[value_size] = 0;
                stream->saw_method = 1;
            }
        } else if (kind == ANKAH_HEADER_PSEUDO_PATH) {
            if (stream->saw_path || value_size >= sizeof(stream->request.target)) stream->invalid = 1;
            else {
                memcpy(stream->request.target, value, value_size);
                stream->request.target[value_size] = 0;
                stream->saw_path = 1;
            }
        } else if (kind == ANKAH_HEADER_PSEUDO_AUTHORITY) {
            if (stream->saw_authority || value_size >= sizeof(stream->authority)) stream->invalid = 1;
            else {
                memcpy(stream->authority, value, value_size);
                stream->authority[value_size] = 0;
                stream->saw_authority = 1;
            }
        } else if (kind == ANKAH_HEADER_PSEUDO_SCHEME) {
            if (value_size >= sizeof(stream->scheme)) stream->invalid = 1;
            else {
                memcpy(stream->scheme, value, value_size);
                stream->scheme[value_size] = 0;
            }
        } else stream->invalid = 1;
        return 0;
    }
    stream->regular_headers = 1;
    if (stream->request.count >= ANKAH_MAX_HEADERS || name_size >= ANKAH_MAX_FIELD ||
        value_size >= ANKAH_MAX_VALUE) { stream->invalid = 1; return 0; }
    header = &stream->request.headers[stream->request.count++];
    if (ankah_header_set_name(header, (const char *)name, name_size) != 0) {
        stream->invalid = 1;
        return 0;
    }
    memcpy(header->value, value, value_size);
    header->value[value_size] = 0;
    return 0;
}

static int h2_queue_response_body(h2_stream *stream, const void *data, size_t size) {
    buffer_chunk *chunk;
    if (!size) return 0;
    if (size > H2_MAX_RESPONSE_QUEUE - stream->response_queued) return -1;
    chunk = chunk_new(data, size);
    if (!chunk) return -1;
    if (stream->response_last) stream->response_last->next = chunk;
    else stream->response_first = chunk;
    stream->response_last = chunk;
    stream->response_queued += size;
    return 0;
}

static ssize_t h2_data_read(nghttp2_session *session, int32_t stream_id,
                            uint8_t *buffer, size_t length, uint32_t *flags,
                            nghttp2_data_source *source, void *user_data) {
    h2_stream *stream = source->ptr;
    buffer_chunk *chunk;
    size_t available;
    (void)session;
    (void)stream_id;
    (void)user_data;
    chunk = stream->response_first;
    if (!chunk) {
        if (stream->response_complete) {
            *flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        return NGHTTP2_ERR_DEFERRED;
    }
    available = chunk->size - chunk->offset;
    if (length > available) length = available;
    memcpy(buffer, chunk->data + chunk->offset, length);
    chunk->offset += length;
    stream->response_queued -= length;
    if (chunk->offset == chunk->size) {
        stream->response_first = chunk->next;
        if (!stream->response_first) stream->response_last = NULL;
        free(chunk);
    }
    if (!stream->response_first && stream->response_complete)
        *flags |= NGHTTP2_DATA_FLAG_EOF;
    if (stream->core_read_stopped && stream->response_queued < H2_MAX_RESPONSE_QUEUE / 2 &&
        stream->core_initialized && !stream->closed_by_h2) {
        if (uv_read_start((uv_stream_t *)&stream->core, allocate_read,
                          on_h2_core_read) == 0) stream->core_read_stopped = 0;
    }
    return (ssize_t)length;
}

static int response_hop_header(const ankah_header *header) {
    unsigned char kind = ankah_header_effective_kind(header);
    return kind == ANKAH_HEADER_CONNECTION || kind == ANKAH_HEADER_KEEP_ALIVE ||
           kind == ANKAH_HEADER_PROXY_CONNECTION ||
           kind == ANKAH_HEADER_TRANSFER_ENCODING || kind == ANKAH_HEADER_UPGRADE ||
           kind == ANKAH_HEADER_HTTP2_SETTINGS || kind == ANKAH_HEADER_TE;
}

static int response_connection_names(const h2_stream *stream, const char *name) {
    unsigned int i;
    for (i = 0; i < stream->response_count; ++i) {
        const char *p;
        if (!ankah_header_is(&stream->response_headers[i], ANKAH_HEADER_CONNECTION)) continue;
        p = stream->response_headers[i].value;
        while (*p) {
            const char *start, *end;
            while (*p == ',' || *p == ' ' || *p == '\t') ++p;
            start = p;
            while (*p && *p != ',') ++p;
            end = p;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
            if (same_ascii_part(start, (size_t)(end - start), name, strlen(name))) return 1;
        }
    }
    return 0;
}

static void lower_header_names(h2_stream *stream, unsigned int first) {
    unsigned int i;
    for (i = first; i < stream->response_count; ++i) {
        char *p;
        for (p = stream->response_headers[i].name; *p; ++p)
            if (*p >= 'A' && *p <= 'Z') *p = (char)(*p + 32);
    }
}

static int submit_h2_trailers(h2_stream *stream) {
    nghttp2_nv values[ANKAH_MAX_HEADERS];
    size_t count = 0;
    unsigned int i;
    lower_header_names(stream, stream->response_initial_count);
    for (i = stream->response_initial_count; i < stream->response_count; ++i) {
        ankah_header *header = &stream->response_headers[i];
        if (response_hop_header(header) ||
            response_connection_names(stream, header->name)) continue;
        values[count].name = (uint8_t *)header->name;
        values[count].namelen = strlen(header->name);
        values[count].value = (uint8_t *)header->value;
        values[count].valuelen = strlen(header->value);
        values[count].flags = NGHTTP2_NV_FLAG_NONE;
        ++count;
    }
    return count ? nghttp2_submit_trailer(stream->front->h2, stream->id,
                                           values, count) : 0;
}

static int submit_h2_headers(h2_stream *stream) {
    nghttp2_nv values[ANKAH_MAX_HEADERS + 1];
    nghttp2_data_provider provider;
    char status[4];
    size_t count = 0;
    unsigned int i;
    int result;
    lower_header_names(stream, 0);
    snprintf(status, sizeof(status), "%03d", stream->response_status);
#define NV(NAME, VALUE) {(uint8_t *)(NAME), (uint8_t *)(VALUE), strlen(NAME), strlen(VALUE), NGHTTP2_NV_FLAG_NONE}
    values[count++] = (nghttp2_nv)NV(":status", status);
    for (i = 0; i < stream->response_count; ++i) {
        ankah_header *header = &stream->response_headers[i];
        if (response_hop_header(header) ||
            response_connection_names(stream, header->name)) continue;
        values[count].name = (uint8_t *)header->name;
        values[count].namelen = strlen(header->name);
        values[count].value = (uint8_t *)header->value;
        values[count].valuelen = strlen(header->value);
        values[count].flags = NGHTTP2_NV_FLAG_NONE;
        ++count;
    }
#undef NV
    stream->response_has_body = strcmp(stream->request.method, "HEAD") != 0 &&
        stream->response_status != 204 && stream->response_status != 304;
    if (stream->response_has_body) {
        memset(&provider, 0, sizeof(provider));
        provider.source.ptr = stream;
        provider.read_callback = h2_data_read;
        result = nghttp2_submit_response(stream->front->h2, stream->id,
                                         values, count, &provider);
        stream->data_submitted = result == 0;
    } else result = nghttp2_submit_response(stream->front->h2, stream->id,
                                             values, count, NULL);
    return result;
}

static int append_response_field(h2_stream *stream, const char *data, size_t size) {
    ankah_header *header;
    if (stream->response_count >= ANKAH_MAX_HEADERS) return -1;
    header = &stream->response_headers[stream->response_count];
    if (stream->response_stage == 2) {
        ++stream->response_count;
        if (stream->response_count >= ANKAH_MAX_HEADERS) return -1;
        header = &stream->response_headers[stream->response_count];
    }
    stream->response_stage = 1;
    return append_text(header->name, sizeof(header->name), (const uint8_t *)data, size);
}

static int append_response_value(h2_stream *stream, const char *data, size_t size) {
    ankah_header *header;
    if (stream->response_count >= ANKAH_MAX_HEADERS ||
        (stream->response_stage != 1 && stream->response_stage != 2)) return -1;
    header = &stream->response_headers[stream->response_count];
    if (stream->response_stage == 1) ankah_header_classify(header);
    stream->response_stage = 2;
    return append_text(header->value, sizeof(header->value), (const uint8_t *)data, size);
}

static int response_message_begin(llhttp_t *parser) {
    h2_stream *stream = parser->data;
    if (stream->response_final) return HPE_USER;
    memset(stream->response_headers, 0, sizeof(stream->response_headers));
    stream->response_count = 0;
    stream->response_stage = 0;
    stream->response_status = 0;
    return 0;
}

static int response_header_field(llhttp_t *parser, const char *at, size_t length) {
    return append_response_field(parser->data, at, length);
}

static int response_header_value(llhttp_t *parser, const char *at, size_t length) {
    return append_response_value(parser->data, at, length);
}

static int response_headers_complete(llhttp_t *parser) {
    h2_stream *stream = parser->data;
    stream->response_status = llhttp_get_status_code(parser);
    if (stream->response_stage == 2) ++stream->response_count;
    if (stream->response_status < 200) return 0;
    stream->response_final = 1;
    stream->response_initial_count = stream->response_count;
    stream->response_stage = 0;
    return submit_h2_headers(stream) == 0 ? 0 : HPE_USER;
}

static int response_body(llhttp_t *parser, const char *at, size_t length) {
    h2_stream *stream = parser->data;
    if (!stream->response_final) return 0;
    return h2_queue_response_body(stream, at, length) == 0 ? 0 : HPE_USER;
}

static int response_message_complete(llhttp_t *parser) {
    h2_stream *stream = parser->data;
    if (stream->response_final) {
        if (stream->response_stage == 2) ++stream->response_count;
        if (submit_h2_trailers(stream) != 0) return HPE_USER;
        stream->response_complete = 1;
    }
    return 0;
}

static void h2_local_response(h2_stream *stream, int status, const char *body) {
    char status_text[4], length_text[32];
    nghttp2_nv headers[4];
    nghttp2_data_provider provider;
    snprintf(status_text, sizeof(status_text), "%d", status);
    snprintf(length_text, sizeof(length_text), "%zu", strlen(body));
#define NV2(NAME, VALUE) {(uint8_t *)(NAME), (uint8_t *)(VALUE), strlen(NAME), strlen(VALUE), NGHTTP2_NV_FLAG_NONE}
    headers[0] = (nghttp2_nv)NV2(":status", status_text);
    headers[1] = (nghttp2_nv)NV2("content-type", "text/plain");
    headers[2] = (nghttp2_nv)NV2("content-length", length_text);
    headers[3] = (nghttp2_nv)NV2("cache-control", "no-store");
#undef NV2
    stream->response_status = status;
    stream->response_final = 1;
    stream->response_complete = 1;
    stream->response_has_body = 1;
    if (h2_queue_response_body(stream, body, strlen(body)) != 0) {
        nghttp2_submit_rst_stream(stream->front->h2, NGHTTP2_FLAG_NONE,
                                  stream->id, NGHTTP2_INTERNAL_ERROR);
        return;
    }
    memset(&provider, 0, sizeof(provider));
    provider.source.ptr = stream;
    provider.read_callback = h2_data_read;
    if (nghttp2_submit_response(stream->front->h2, stream->id,
                                headers, 4, &provider) == 0) stream->data_submitted = 1;
}

static void on_h2_core_read(uv_stream_t *handle, ssize_t count, const uv_buf_t *buffer) {
    h2_stream *stream = handle->data;
    front_connection *front = stream->front;
    if (count > 0 && !front->closing && !stream->closed_by_h2) {
        llhttp_errno_t error;
        refresh_timeout(front);
        error = llhttp_execute(&stream->response_parser, buffer->base, (size_t)count);
        if (error != HPE_OK) {
            if (!stream->response_final) h2_local_response(stream, 502, "Invalid upstream response\n");
            else nghttp2_submit_rst_stream(front->h2, NGHTTP2_FLAG_NONE,
                                           stream->id, NGHTTP2_INTERNAL_ERROR);
            close_stream_core(stream);
        } else {
            if (stream->data_submitted)
                nghttp2_session_resume_data(front->h2, stream->id);
            if (stream->response_queued >= H2_MAX_RESPONSE_QUEUE - 16384U) {
                uv_read_stop(handle);
                stream->core_read_stopped = 1;
            }
            h2_flush(front);
            drive_tls(front);
        }
    } else if (count < 0 && !front->closing && !stream->closed_by_h2) {
        llhttp_errno_t error = llhttp_finish(&stream->response_parser);
        if (error != HPE_OK || !stream->response_final) {
            if (!stream->response_final) h2_local_response(stream, 502, "Incomplete upstream response\n");
            else nghttp2_submit_rst_stream(front->h2, NGHTTP2_FLAG_NONE,
                                           stream->id, NGHTTP2_INTERNAL_ERROR);
        } else stream->response_complete = 1;
        if (stream->data_submitted) nghttp2_session_resume_data(front->h2, stream->id);
        h2_flush(front);
        drive_tls(front);
        close_stream_core(stream);
    }
    free(buffer->base);
}

static void on_h2_core_connected(uv_connect_t *request, int status) {
    h2_stream *stream = request->data;
    front_connection *front = stream->front;
    char *head;
    size_t capacity, used = 0;
    unsigned int i;
    int length;
    uv_buf_t buffers[2];
    bridge_write *write;
    if (status < 0 || front->closing || stream->closed_by_h2) {
        if (!front->closing && !stream->closed_by_h2) {
            h2_local_response(stream, 502, "Upstream unavailable\n");
            h2_flush(front);
            drive_tls(front);
        }
        close_stream_core(stream);
        return;
    }
    stream->core_connected = 1;
    capacity = ANKAH_HEADER_LIMIT + 512;
    head = malloc(capacity);
    if (!head) { close_front(front); return; }
    length = snprintf(head, capacity, "%s %s HTTP/1.1\r\nHost: %s\r\n",
                      stream->request.method, stream->request.target, stream->authority);
    if (length < 0 || (size_t)length >= capacity) { free(head); close_front(front); return; }
    used = (size_t)length;
    for (i = 0; i < stream->request.count; ++i) {
        ankah_header *header = &stream->request.headers[i];
        unsigned char kind = ankah_header_effective_kind(header);
        if (kind == ANKAH_HEADER_HOST || kind == ANKAH_HEADER_CONTENT_LENGTH ||
            kind == ANKAH_HEADER_CONNECTION || kind == ANKAH_HEADER_TRANSFER_ENCODING ||
            kind == ANKAH_HEADER_EXPECT || kind == ANKAH_HEADER_X_ANKAH_INTERNAL_KEY ||
            kind == ANKAH_HEADER_X_ANKAH_INTERNAL_PEER) continue;
        length = snprintf(head + used, capacity - used, "%s: %s\r\n",
                          header->name, header->value);
        if (length < 0 || (size_t)length >= capacity - used) {
            free(head); close_front(front); return;
        }
        used += (size_t)length;
    }
    length = snprintf(head + used, capacity - used,
                      "Content-Length: %zu\r\nX-Ankah-Internal-Key: %s\r\n"
                      "X-Ankah-Internal-Peer: %s\r\n\r\n",
                      stream->body_size, frontend.options.internal_key,
                      front->peer_ip);
    if (length < 0 || (size_t)length >= capacity - used) {
        free(head); close_front(front); return;
    }
    used += (size_t)length;
    write = calloc(1, sizeof(*write));
    if (!write) { free(head); close_front(front); return; }
    write->buffer.base = malloc(used + stream->body_size);
    if (!write->buffer.base) { free(write); free(head); close_front(front); return; }
    memcpy(write->buffer.base, head, used);
    if (stream->body_size) memcpy(write->buffer.base + used, stream->body, stream->body_size);
    write->buffer.len = (unsigned int)(used + stream->body_size);
    write->front = front;
    write->request.data = write;
    buffers[0] = write->buffer;
    free(head);
    if (uv_write(&write->request, (uv_stream_t *)&stream->core,
                 buffers, 1, on_bridge_write) != 0) {
        free(write->buffer.base);
        free(write);
        h2_local_response(stream, 502, "Upstream unavailable\n");
        close_stream_core(stream);
        return;
    }
    ++front->bridge_pending;
    llhttp_settings_init(&stream->response_settings);
    stream->response_settings.on_message_begin = response_message_begin;
    stream->response_settings.on_header_field = response_header_field;
    stream->response_settings.on_header_value = response_header_value;
    stream->response_settings.on_headers_complete = response_headers_complete;
    stream->response_settings.on_body = response_body;
    stream->response_settings.on_message_complete = response_message_complete;
    llhttp_init(&stream->response_parser, HTTP_RESPONSE, &stream->response_settings);
    stream->response_parser.data = stream;
    if (uv_read_start((uv_stream_t *)&stream->core, allocate_read, on_h2_core_read) != 0)
        close_stream_core(stream);
}

static int valid_content_length(h2_stream *stream) {
    const char *value = ankah_header_value(&stream->request, "content-length");
    size_t parsed = 0, i;
    if (!value) return 1;
    if (!*value) return 0;
    for (i = 0; value[i]; ++i) {
        unsigned int digit;
        if (value[i] < '0' || value[i] > '9') return 0;
        digit = (unsigned int)(value[i] - '0');
        if (parsed > (SIZE_MAX - digit) / 10) return 0;
        parsed = parsed * 10 + digit;
    }
    return parsed == stream->body_size;
}

static void h2_dispatch(h2_stream *stream) {
    struct sockaddr_in address;
    front_connection *front = stream->front;
    if (stream->dispatched || stream->closed_by_h2) return;
    stream->dispatched = 1;
    if (stream->invalid || !stream->saw_method || !stream->saw_path ||
        !stream->saw_authority || stream->request.target[0] != '/' ||
        strcmp(stream->scheme, "https") != 0 || !valid_content_length(stream)) {
        h2_local_response(stream, 400, "Invalid HTTP/2 request\n");
        return;
    }
    if (uv_ip4_addr("127.0.0.1", frontend.options.internal_port, &address) != 0 ||
        uv_tcp_init(frontend.options.loop, &stream->core) != 0) {
        h2_local_response(stream, 503, "Unavailable\n");
        return;
    }
    stream->core_initialized = 1;
    ++front->handles;
    stream->core.data = stream;
    stream->core_connect.data = stream;
    if (uv_tcp_connect(&stream->core_connect, &stream->core,
                       (const struct sockaddr *)&address, on_h2_core_connected) != 0) {
        h2_local_response(stream, 502, "Upstream unavailable\n");
        close_stream_core(stream);
    }
}

static int h2_on_frame_recv(nghttp2_session *session,
                            const nghttp2_frame *frame, void *user_data) {
    front_connection *front = user_data;
    h2_stream *stream = find_stream(front, frame->hd.stream_id);
    (void)session;
    if (stream && (frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) h2_dispatch(stream);
    return 0;
}

static int h2_on_data(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                      const uint8_t *data, size_t size, void *user_data) {
    front_connection *front = user_data;
    h2_stream *stream = find_stream(front, stream_id);
    unsigned char *replacement;
    (void)session;
    (void)flags;
    if (!stream || stream->invalid || stream->dispatched) return 0;
    if (size > H2_MAX_BODY - stream->body_size ||
        size > H2_MAX_BODY_TOTAL - front->h2_body_total) {
        stream->invalid = 1;
        return 0;
    }
    if (stream->body_size + size > stream->body_capacity) {
        size_t capacity = stream->body_capacity ? stream->body_capacity * 2 : 8192;
        while (capacity < stream->body_size + size) capacity *= 2;
        replacement = realloc(stream->body, capacity);
        if (!replacement) { stream->invalid = 1; return 0; }
        stream->body = replacement;
        stream->body_capacity = capacity;
    }
    memcpy(stream->body + stream->body_size, data, size);
    stream->body_size += size;
    front->h2_body_total += size;
    return 0;
}

static int h2_on_stream_close(nghttp2_session *session, int32_t stream_id,
                              uint32_t error_code, void *user_data) {
    front_connection *front = user_data;
    h2_stream *stream = find_stream(front, stream_id);
    (void)session;
    (void)error_code;
    if (!stream) return 0;
    stream->closed_by_h2 = 1;
    front->h2_body_total -= stream->body_size;
    free(stream->body);
    stream->body = NULL;
    stream->body_size = 0;
    free_chunks(stream->response_first);
    stream->response_first = stream->response_last = NULL;
    stream->response_queued = 0;
    close_stream_core(stream);
    stream_maybe_free(stream);
    return 0;
}

static int init_h2(front_connection *front) {
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, H2_MAX_STREAMS},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, ANKAH_HEADER_LIMIT}
    };
    int result = nghttp2_session_callbacks_new(&callbacks);
    if (result != 0) return -1;
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, h2_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_on_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_on_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2_on_stream_close);
    result = nghttp2_session_server_new(&front->h2, callbacks, front);
    nghttp2_session_callbacks_del(callbacks);
    if (result != 0) return -1;
    return nghttp2_submit_settings(front->h2, NGHTTP2_FLAG_NONE,
                                   settings, sizeof(settings) / sizeof(settings[0]));
}

static void h2_flush(front_connection *front) {
    const uint8_t *data;
    ssize_t size;
    if (!front->h2 || front->closing) return;
    while (front->plain_queued <= FRONT_MAX_PLAIN_OUTPUT - 65536U) {
        size = nghttp2_session_mem_send(front->h2, &data);
        if (size < 0) { close_front(front); return; }
        if (!size) return;
        if (queue_plain(front, data, (size_t)size) != 0) {
            close_front(front);
            return;
        }
    }
}

static void consume_plain(front_connection *front, size_t size) {
    buffer_chunk *chunk = front->plain_first;
    chunk->offset += size;
    front->plain_queued -= size;
    if (chunk->offset == chunk->size) {
        front->plain_first = chunk->next;
        if (!front->plain_first) front->plain_last = NULL;
        free(chunk);
    }
    if (!front->protocol_h2 && front->bridge_initialized && front->plain_queued < FRONT_MAX_PLAIN_OUTPUT / 2)
        uv_read_start((uv_stream_t *)&front->bridge, allocate_read, on_bridge_read);
}

static void drive_tls(front_connection *front) {
    unsigned char plain[16384];
    int result;
    if (front->closing) return;
    if (front->driving) { front->drive_again = 1; return; }
    front->driving = 1;
    do {
        front->drive_again = 0;
        if (!front->handshake_complete) {
            result = mbedtls_ssl_handshake(&front->ssl);
            if (result == 0) {
                const char *protocol = mbedtls_ssl_get_alpn_protocol(&front->ssl);
                front->handshake_complete = 1;
                front->protocol_h2 = protocol && strcmp(protocol, "h2") == 0;
                refresh_timeout(front);
                if (front->protocol_h2) {
                    if (init_h2(front) != 0) { close_front(front); break; }
                    h2_flush(front);
                } else if (connect_h1_bridge(front) != 0) {
                    close_front(front);
                    break;
                }
            } else if (result != MBEDTLS_ERR_SSL_WANT_READ &&
                       result != MBEDTLS_ERR_SSL_WANT_WRITE) {
                close_front(front);
                break;
            }
        }
        if (!front->handshake_complete) continue;
        if (front->protocol_h2) h2_flush(front);
        while (front->plain_first && !front->closing) {
            buffer_chunk *chunk = front->plain_first;
            result = mbedtls_ssl_write(&front->ssl, chunk->data + chunk->offset,
                                       chunk->size - chunk->offset);
            if (result > 0) consume_plain(front, (size_t)result);
            else if (result == MBEDTLS_ERR_SSL_WANT_READ ||
                     result == MBEDTLS_ERR_SSL_WANT_WRITE) break;
            else { close_front(front); break; }
        }
        if (front->closing) break;
        if (front->close_notify_started && !front->plain_first) {
            if (!front->close_notify_sent) {
                result = mbedtls_ssl_close_notify(&front->ssl);
                if (result == 0) front->close_notify_sent = 1;
                else if (result != MBEDTLS_ERR_SSL_WANT_READ &&
                         result != MBEDTLS_ERR_SSL_WANT_WRITE) close_front(front);
            }
            if (front->close_notify_sent && !front->cipher_pending) close_front(front);
            continue;
        }
        if (!front->protocol_h2 && !front->bridge_connected) continue;
        while (!front->closing && front->bridge_pending < 8) {
            result = mbedtls_ssl_read(&front->ssl, plain, sizeof(plain));
            if (result > 0) {
                refresh_timeout(front);
                if (front->protocol_h2) {
                    ssize_t used = nghttp2_session_mem_recv(front->h2, plain, (size_t)result);
                    if (used < 0 || used != result) { close_front(front); break; }
                    h2_flush(front);
                } else if (forward_h1_plain(front, plain, (size_t)result) != 0) {
                    close_front(front);
                    break;
                }
            } else if (result == 0 || result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                close_front(front);
                break;
            } else if (result == MBEDTLS_ERR_SSL_WANT_READ ||
                       result == MBEDTLS_ERR_SSL_WANT_WRITE) break;
            else { close_front(front); break; }
        }
    } while (front->drive_again && !front->closing);
    front->driving = 0;
}

static void on_client_read(uv_stream_t *handle, ssize_t count, const uv_buf_t *buffer) {
    front_connection *front = handle->data;
    if (count > 0 && !front->closing) {
        refresh_timeout(front);
        if (append_cipher(front, buffer->base, (size_t)count) != 0) close_front(front);
        else drive_tls(front);
    } else if (count < 0 && !front->closing) close_front(front);
    free(buffer->base);
}

static void on_timeout(uv_timer_t *timer) {
    close_front(timer->data);
}

static int peer_text(uv_tcp_t *client, char *out, size_t capacity) {
    struct sockaddr_storage address;
    int size = sizeof(address);
    if (uv_tcp_getpeername(client, (struct sockaddr *)&address, &size) != 0) return -1;
    if (address.ss_family == AF_INET)
        return uv_ip4_name((const struct sockaddr_in *)&address, out, capacity);
    if (address.ss_family == AF_INET6)
        return uv_ip6_name((const struct sockaddr_in6 *)&address, out, capacity);
    return -1;
}

unsigned int ankah_frontend_connections(void) {
    return frontend.connections;
}

void ankah_frontend_accept(uv_stream_t *server, int status) {
    front_connection *front;
    int result;
    if (status < 0) return;
    if (frontend.connections >= FRONT_MAX_CONNECTIONS) {
        uv_tcp_t *discard = malloc(sizeof(*discard));
        ankah_stats_add(ANKAH_STAT_refused, 1);
        if (discard && uv_tcp_init(frontend.options.loop, discard) == 0) {
            uv_accept(server, (uv_stream_t *)discard);
            uv_close((uv_handle_t *)discard, on_discard_closed);
        } else free(discard);
        return;
    }
    front = calloc(1, sizeof(*front));
    if (!front) return;
    mbedtls_ssl_init(&front->ssl);
    if (uv_tcp_init(frontend.options.loop, &front->client) != 0) {
        mbedtls_ssl_free(&front->ssl); free(front); return;
    }
    front->client.data = front;
    front->handles = 1;
    ++frontend.connections;
    if (uv_accept(server, (uv_stream_t *)&front->client) != 0 ||
        peer_text(&front->client, front->peer_ip, sizeof(front->peer_ip)) != 0) {
        close_front(front);
        return;
    }
    front->credentials = frontend.active;
    ++front->credentials->references;
    result = mbedtls_ssl_setup(&front->ssl, &front->credentials->config);
    if (result != 0) {
        close_front(front);
        return;
    }
    mbedtls_ssl_set_bio(&front->ssl, front, tls_send, tls_receive, NULL);
    if (uv_timer_init(frontend.options.loop, &front->timer) != 0) {
        close_front(front);
        return;
    }
    front->timer_initialized = 1;
    front->timer.data = front;
    ++front->handles;
    refresh_timeout(front);
    if (uv_read_start((uv_stream_t *)&front->client, allocate_read, on_client_read) != 0)
        close_front(front);
}

int ankah_frontend_init(const ankah_frontend_options *options) {
    static const unsigned char personalization[] = "ankah tls";
    int result;
    if (!options || !options->loop || !options->certificate_path ||
        !options->key_path || !options->internal_key || options->internal_port < 1) return -1;
    memset(&frontend, 0, sizeof(frontend));
    frontend.options = *options;
    mbedtls_entropy_init(&frontend.entropy);
    mbedtls_ctr_drbg_init(&frontend.random);
    result = mbedtls_ctr_drbg_seed(&frontend.random, mbedtls_entropy_func,
                                   &frontend.entropy, personalization,
                                   sizeof(personalization) - 1);
    if (result != 0) { log_tls_error("random setup", result); return -1; }
    frontend.active = credentials_load();
    if (!frontend.active) return -1;
#ifndef _WIN32
    if (uv_signal_init(options->loop, &frontend.reload_signal) != 0 ||
        uv_signal_start(&frontend.reload_signal, on_reload_signal, SIGHUP) != 0) return -1;
    frontend.reload_signal_initialized = 1;
#else
    {
        char certificate_parent[512], key_parent[512];
        if (parent_path(options->certificate_path, certificate_parent,
                        sizeof(certificate_parent)) != 0 ||
            parent_path(options->key_path, key_parent, sizeof(key_parent)) != 0 ||
            uv_timer_init(options->loop, &frontend.reload_timer) != 0) return -1;
        frontend.reload_timer_initialized = 1;
        if (uv_fs_event_init(options->loop, &frontend.certificate_watch) != 0 ||
            uv_fs_event_start(&frontend.certificate_watch, on_credential_change,
                              certificate_parent, 0) != 0) return -1;
        frontend.certificate_watch_initialized = 1;
        if (uv_fs_event_init(options->loop, &frontend.key_watch) != 0 ||
            uv_fs_event_start(&frontend.key_watch, on_credential_change,
                              key_parent, 0) != 0) return -1;
        frontend.key_watch_initialized = 1;
    }
#endif
    return 0;
}

void ankah_frontend_shutdown(void) {
#ifndef _WIN32
    if (frontend.reload_signal_initialized &&
        !uv_is_closing((uv_handle_t *)&frontend.reload_signal))
        uv_close((uv_handle_t *)&frontend.reload_signal, NULL);
#else
    if (frontend.certificate_watch_initialized &&
        !uv_is_closing((uv_handle_t *)&frontend.certificate_watch))
        uv_close((uv_handle_t *)&frontend.certificate_watch, NULL);
    if (frontend.key_watch_initialized &&
        !uv_is_closing((uv_handle_t *)&frontend.key_watch))
        uv_close((uv_handle_t *)&frontend.key_watch, NULL);
    if (frontend.reload_timer_initialized &&
        !uv_is_closing((uv_handle_t *)&frontend.reload_timer))
        uv_close((uv_handle_t *)&frontend.reload_timer, NULL);
#endif
    if (frontend.active) {
        frontend.active->retired = 1;
        if (!frontend.active->references) credentials_free(frontend.active);
        frontend.active = NULL;
    }
    mbedtls_ctr_drbg_free(&frontend.random);
    mbedtls_entropy_free(&frontend.entropy);
}
