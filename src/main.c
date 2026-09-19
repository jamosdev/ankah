#include "ankah/http.h"
#include "ankah/pow.h"
#include "ankah/static.h"
#include "ankah/session.h"
#include "ankah/qr.h"
#include <uv.h>

#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "ankah/sha256.h"
#if ANKAH_HAS_WASM
#include "browser_pow_data.h"
#endif

#define MAX_CONNECTIONS 256
#define MAX_BODY (16U * 1024U * 1024U)
#define MAX_ALLOW 32
#define MAX_PENDING_WRITES 8
#define MAX_ASSET_SIZE (4U * 1024U * 1024U)
#define ASSET_COUNT (8 + ANKAH_HAS_WASM)
#define RATE_BUCKETS 1024
#define MAX_STATIC_RANGES 16
#define MAX_STATIC_SEGMENTS (MAX_STATIC_RANGES * 3 + 1)

typedef struct cache_blob cache_blob;
struct cache_blob {
    cache_blob *previous, *next;
    unsigned char *data;
    char etag[67];
    size_t size;
    unsigned int pins;
};

typedef struct {
    const unsigned char *data;
    size_t size;
} static_segment;

typedef struct {
    char ip[64];
    double tokens;
    uint64_t last_ns;
} rate_bucket;

typedef struct connection connection;
typedef struct {
    uv_write_t request;
    uv_buf_t buffer;
    connection *owner;
    uv_stream_t *source;
    int finish;
} queued_write;

struct connection {
    uv_tcp_t client;
    uv_tcp_t upstream;
    uv_connect_t connect_request;
    uv_timer_t timer;
    ankah_request request;
    char initial[ANKAH_HEADER_LIMIT + 1];
    char peer_ip[64];
    size_t initial_size;
    size_t body_received;
    ankah_session *capture_session;
    unsigned char *replay_body;
    size_t replay_size;
    size_t replay_offset;
    int replaying;
    int capture_continue;
    char continue_body[256];
    size_t continue_received;
    size_t continue_expected;
    unsigned int pending;
    unsigned int handles;
    uint64_t request_deadline_ns;
    int upstream_initialized;
    int timer_initialized;
    int forwarding;
    int closed;
    int websocket;
    int asset_index;
    const ankah_static_entry *static_entry;
    cache_blob *cache_pin;
    static_segment segments[MAX_STATIC_SEGMENTS];
    unsigned int segment_count, segment_index;
    size_t segment_offset;
    char segment_headers[8192];
    size_t segment_headers_used;
    size_t asset_offset;
};

typedef struct {
    const char *name;
    const char *type;
    const unsigned char *data;
    size_t size;
    char etag[67];
    char last_modified[64];
    time_t modified;
} static_asset;

typedef struct {
    char listen_ip[64];
    int listen_port;
    char upstream_ip[64];
    int upstream_port;
    char public_origin[256];
    char public_host[256];
    int public_https;
    char secret_path[512];
    char assets_dir[512];
    char static_dir[512];
    const char *allow[MAX_ALLOW];
    unsigned int allow_count;
    unsigned char secret[ANKAH_SECRET_SIZE];
    uv_loop_t *loop;
    uv_tcp_t listener;
    uv_process_t child;
    int child_started;
    unsigned int connections;
    static_asset assets[ASSET_COUNT];
    ankah_static_bundle static_bundle;
    size_t static_cache_limit, static_cache_used;
    cache_blob *cache_first, *cache_last;
    rate_bucket rates[RATE_BUCKETS];
    double global_tokens;
    uint64_t global_last_ns;
} configuration;

static configuration config;

static void close_connection(connection *c);
static void send_asset_chunk(connection *c);
static void send_replay_chunk(connection *c);
static int queue_bytes(connection *c, uv_stream_t *destination,
                       uv_stream_t *source, const char *data, size_t length, int finish);
static void respond(connection *c, int status, const char *reason,
                    const char *type, const char *body, const char *extra);
static int etag_matches(const ankah_request *request, const char *etag);
static void on_client_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer);
static void on_upstream_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer);
static size_t header_end(const char *bytes, size_t length);

static int same_ascii(const char *left, const char *right) {
    unsigned char a, b;
    while (*left && *right) {
        a = (unsigned char)*left++;
        b = (unsigned char)*right++;
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
        if (a != b) return 0;
    }
    return *left == *right;
}

static int same_ascii_part(const char *left, size_t length, const char *right) {
    size_t i;
    if (strlen(right) != length) return 0;
    for (i = 0; i < length; ++i) {
        unsigned char a = (unsigned char)left[i];
        unsigned char b = (unsigned char)right[i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
        if (a != b) return 0;
    }
    return 1;
}

static int starts_ascii(const char *value, const char *start) {
    size_t length = strlen(start);
    return strlen(value) >= length && same_ascii_part(value, length, start);
}

static void respond_binary(connection *c, const char *type,
                           const unsigned char *body, size_t size) {
    char head[512];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                     "Referrer-Policy: no-referrer\r\nConnection: close\r\n\r\n", type, size);
    if (n < 0 || (size_t)n >= sizeof(head) || size + (size_t)n > 65536) {
        close_connection(c);
        return;
    }
    {
        unsigned char *packet = malloc((size_t)n + size);
        if (!packet) { close_connection(c); return; }
        memcpy(packet, head, (size_t)n);
        memcpy(packet + n, body, size);
        if (queue_bytes(c, (uv_stream_t *)&c->client, NULL,
                        (const char *)packet, (size_t)n + size, 1) != 0)
            close_connection(c);
        free(packet);
    }
}

static ankah_session *request_session(const ankah_request *request) {
    const char *cookie = ankah_header_value(request, "Cookie");
    const char *item;
    char id[33];
    if (!cookie) return NULL;
    item = strstr(cookie, "ankah_sid=");
    if (!item || (item != cookie && item[-1] != ';' && item[-1] != ' ')) return NULL;
    item += strlen("ankah_sid=");
    if (strspn(item, "0123456789abcdef") != 32 ||
        (item[32] != ';' && item[32] != ' ' && item[32] != 0)) return NULL;
    memcpy(id, item, 32);
    id[32] = 0;
    return ankah_session_find(id, (uint64_t)time(NULL));
}

static int html_escape(const char *source, char *out, size_t capacity) {
    size_t used = 0;
    while (*source) {
        const char *replacement = NULL;
        if (*source == '&') replacement = "&amp;";
        else if (*source == '<') replacement = "&lt;";
        else if (*source == '>') replacement = "&gt;";
        else if (*source == '\'') replacement = "&#39;";
        else if (*source == '"') replacement = "&quot;";
        if (replacement) {
            size_t n = strlen(replacement);
            if (used + n >= capacity) return -1;
            memcpy(out + used, replacement, n);
            used += n;
        } else {
            if (used + 1 >= capacity) return -1;
            out[used++] = *source;
        }
        ++source;
    }
    out[used] = 0;
    return 0;
}

static int prefix(const char *value, const char *start) {
    return strncmp(value, start, strlen(start)) == 0;
}

static int allow_rate(const char *ip) {
    uint64_t now = uv_hrtime();
    rate_bucket *bucket = NULL, *oldest = &config.rates[0];
    unsigned int i;
    if (!config.global_last_ns) {
        config.global_last_ns = now;
        config.global_tokens = 1000.0;
    }
    config.global_tokens += (double)(now - config.global_last_ns) / 1000000000.0 * 500.0;
    if (config.global_tokens > 1000.0) config.global_tokens = 1000.0;
    config.global_last_ns = now;
    for (i = 0; i < RATE_BUCKETS; ++i) {
        if (strcmp(config.rates[i].ip, ip) == 0) { bucket = &config.rates[i]; break; }
        if (config.rates[i].last_ns < oldest->last_ns) oldest = &config.rates[i];
    }
    if (!bucket) {
        bucket = oldest;
        strcpy(bucket->ip, ip);
        bucket->tokens = 200.0;
        bucket->last_ns = now;
    }
    bucket->tokens += (double)(now - bucket->last_ns) / 1000000000.0 * 100.0;
    if (bucket->tokens > 200.0) bucket->tokens = 200.0;
    bucket->last_ns = now;
    if (config.global_tokens < 1.0 || bucket->tokens < 1.0) return 0;
    config.global_tokens -= 1.0;
    bucket->tokens -= 1.0;
    return 1;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int decimal_u64(const char *text, uint64_t *out) {
    uint64_t value = 0;
    size_t i;
    if (!text || !text[0]) return -1;
    for (i = 0; text[i]; ++i) {
        unsigned int digit;
        if (text[i] < '0' || text[i] > '9') return -1;
        digit = (unsigned int)(text[i] - '0');
        if (value > (UINT64_MAX - digit) / 10) return -1;
        value = value * 10 + digit;
    }
    *out = value;
    return 0;
}

static void erase_bytes(void *data, size_t size) {
    volatile unsigned char *bytes = data;
    while (size--) *bytes++ = 0;
}

static int load_secret(const char *path) {
    char input[65];
    struct stat metadata;
    size_t size = 0, i;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) ||
        (metadata.st_size != 64 && metadata.st_size != 65)) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    while (size < (size_t)metadata.st_size) {
        ssize_t amount = read(descriptor, input + size,
                              (size_t)metadata.st_size - size);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { close(descriptor); erase_bytes(input, sizeof(input)); return -1; }
        size += (size_t)amount;
    }
    close(descriptor);
    if (size == 65 && input[64] == '\n') size = 64;
    if (size != 64) { erase_bytes(input, sizeof(input)); return -1; }
    for (i = 0; i < ANKAH_SECRET_SIZE; ++i) {
        int high = hex_value(input[i * 2]);
        int low = hex_value(input[i * 2 + 1]);
        if (high < 0 || low < 0) {
            erase_bytes(input, sizeof(input));
            erase_bytes(config.secret, sizeof(config.secret));
            return -1;
        }
        config.secret[i] = (unsigned char)((high << 4) | low);
    }
    erase_bytes(input, sizeof(input));
    return 0;
}

static int finish_asset(static_asset *asset) {
    static const char digits[] = "0123456789abcdef";
    unsigned char digest[32];
    size_t i;
    if (ankah_sha256(asset->data, asset->size, digest) != 0) return -1;
    asset->etag[0] = '"';
    for (i = 0; i < sizeof(digest); ++i) {
        asset->etag[1 + i * 2] = digits[digest[i] >> 4];
        asset->etag[2 + i * 2] = digits[digest[i] & 15];
    }
    asset->etag[65] = '"';
    asset->etag[66] = 0;
    return strftime(asset->last_modified, sizeof(asset->last_modified),
                    "%a, %d %b %Y %H:%M:%S GMT", gmtime(&asset->modified)) ? 0 : -1;
}

static int load_asset(static_asset *asset, const char *directory) {
    struct stat metadata;
    char path[1024];
    FILE *file;
    unsigned char *data;
    size_t i;
    int length = snprintf(path, sizeof(path), "%s/%s", directory, asset->name);
    if (length < 0 || (size_t)length >= sizeof(path) ||
        stat(path, &metadata) != 0 || metadata.st_size < 0 ||
        (uint64_t)metadata.st_size > MAX_ASSET_SIZE) return -1;
    asset->size = (size_t)metadata.st_size;
    asset->modified = metadata.st_mtime;
    data = (unsigned char *)malloc(asset->size + 1);
    if (!data) return -1;
    file = fopen(path, "rb");
    if (!file) { free(data); return -1; }
    i = fread(data, 1, asset->size, file);
    fclose(file);
    data[asset->size] = 0;
    if (i != asset->size) { free(data); return -1; }
    asset->data = data;
    return finish_asset(asset);
}

static int load_assets(void) {
    static const char *names[ASSET_COUNT] = {
        "ankah.png", "particles.min.js", "particlejs.json", "challenge.js",
        "solver.py", "challenge-polyglot.txt", "phone-scan.png",
        "pow-worker.js"
#if ANKAH_HAS_WASM
        , "browser_pow.wasm"
#endif
    };
    static const char *types[ASSET_COUNT] = {
        "image/png", "application/javascript; charset=utf-8",
        "application/json; charset=utf-8", "application/javascript; charset=utf-8",
        "text/x-python; charset=utf-8", "text/plain; charset=utf-8", "image/png",
        "application/javascript; charset=utf-8"
#if ANKAH_HAS_WASM
        , "application/wasm"
#endif
    };
    unsigned int i;
    for (i = 0; i < ASSET_COUNT; ++i) {
        config.assets[i].name = names[i];
        config.assets[i].type = types[i];
        if (i == 8) {
#if ANKAH_HAS_WASM
            config.assets[i].data = ankah_browser_pow_data;
            config.assets[i].size = sizeof(ankah_browser_pow_data);
            config.assets[i].modified = 0;
            if (finish_asset(&config.assets[i]) != 0) return -1;
#endif
        } else if (load_asset(&config.assets[i], config.assets_dir) != 0) return -1;
    }
    return 0;
}

static int parse_address(const char *input, char *ip, size_t capacity, int *port) {
    const char *colon = strrchr(input, ':');
    char *end;
    long value;
    size_t length;
    if (!colon) return -1;
    length = (size_t)(colon - input);
    if (length == 0 || length >= capacity) return -1;
    memcpy(ip, input, length);
    ip[length] = 0;
    value = strtol(colon + 1, &end, 10);
    if (*end || value < 1 || value > 65535) return -1;
    *port = (int)value;
    return 0;
}

static int valid_allow_prefix(const char *value) {
    size_t i, length;
    if (!value || value[0] != '/') return 0;
    length = strlen(value);
    if (length >= ANKAH_MAX_TARGET) return 0;
    for (i = 0; i < length; ++i)
        if ((unsigned char)value[i] < 33 || (unsigned char)value[i] > 126 ||
            value[i] == '#') return 0;
    return 1;
}

static int parse_options(int argc, char **argv, int *child_index) {
    int i;
    strcpy(config.listen_ip, "0.0.0.0");
    config.listen_port = 8000;
    strcpy(config.upstream_ip, "127.0.0.1");
    config.upstream_port = 8001;
    strcpy(config.assets_dir, ".");
    config.static_cache_limit = 64U * 1024U * 1024U;
    *child_index = argc;
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) {
            *child_index = i + 1;
            break;
        }
        if (i + 1 >= argc) return -1;
        if (strcmp(argv[i], "--listen") == 0) {
            if (parse_address(argv[++i], config.listen_ip, sizeof(config.listen_ip),
                              &config.listen_port) != 0) return -1;
        } else if (strcmp(argv[i], "--upstream") == 0) {
            if (parse_address(argv[++i], config.upstream_ip, sizeof(config.upstream_ip),
                              &config.upstream_port) != 0) return -1;
        } else if (strcmp(argv[i], "--public-origin") == 0) {
            if (strlen(argv[++i]) >= sizeof(config.public_origin)) return -1;
            strcpy(config.public_origin, argv[i]);
        } else if (strcmp(argv[i], "--secret-file") == 0) {
            if (strlen(argv[++i]) >= sizeof(config.secret_path)) return -1;
            strcpy(config.secret_path, argv[i]);
        } else if (strcmp(argv[i], "--assets-dir") == 0) {
            if (strlen(argv[++i]) >= sizeof(config.assets_dir)) return -1;
            strcpy(config.assets_dir, argv[i]);
        } else if (strcmp(argv[i], "--static-bundle") == 0) {
            if (strlen(argv[++i]) >= sizeof(config.static_dir)) return -1;
            strcpy(config.static_dir, argv[i]);
        } else if (strcmp(argv[i], "--static-cache-mb") == 0) {
            uint64_t megabytes;
            if (decimal_u64(argv[++i], &megabytes) != 0 ||
                megabytes > SIZE_MAX / (1024U * 1024U)) return -1;
            config.static_cache_limit = (size_t)megabytes * 1024U * 1024U;
        } else if (strcmp(argv[i], "--allow-prefix") == 0) {
            if (config.allow_count == MAX_ALLOW || !valid_allow_prefix(argv[i + 1])) return -1;
            config.allow[config.allow_count++] = argv[++i];
        } else return -1;
    }
    if (!prefix(config.public_origin, "https://") &&
        !prefix(config.public_origin, "http://")) return -1;
    config.public_https = prefix(config.public_origin, "https://");
    {
        const char *host = strstr(config.public_origin, "://") + 3;
        if (!*host || strspn(host, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                  "0123456789.-:") != strlen(host)) return -1;
        strcpy(config.public_host, host);
    }
    if (config.secret_path[0] == 0 || load_secret(config.secret_path) != 0 ||
        load_assets() != 0 ||
        (config.static_dir[0] &&
         ankah_static_load(&config.static_bundle, config.static_dir) != 0)) return -1;
    return 0;
}

static void on_handle_closed(uv_handle_t *handle) {
    connection *c = (connection *)handle->data;
    if (--c->handles == 0) {
        --config.connections;
        free(c);
    }
}

static void close_connection(connection *c) {
    if (c->closed) return;
    c->closed = 1;
    if (c->cache_pin) --c->cache_pin->pins;
    if (c->capture_session) ankah_session_discard(c->capture_session);
    free(c->replay_body);
    c->replay_body = NULL;
    uv_read_stop((uv_stream_t *)&c->client);
    if (c->upstream_initialized) uv_read_stop((uv_stream_t *)&c->upstream);
    if (!uv_is_closing((uv_handle_t *)&c->client))
        uv_close((uv_handle_t *)&c->client, on_handle_closed);
    if (c->upstream_initialized && !uv_is_closing((uv_handle_t *)&c->upstream))
        uv_close((uv_handle_t *)&c->upstream, on_handle_closed);
    if (c->timer_initialized && !uv_is_closing((uv_handle_t *)&c->timer))
        uv_close((uv_handle_t *)&c->timer, on_handle_closed);
}

static void on_timeout(uv_timer_t *timer) {
    close_connection((connection *)timer->data);
}

static void refresh_timeout(connection *c) {
    uint64_t timeout = c->websocket ? 300000 : 30000;
    if (c->request_deadline_ns) {
        uint64_t now = uv_hrtime(), remaining;
        if (now >= c->request_deadline_ns) {
            close_connection(c);
            return;
        }
        remaining = (c->request_deadline_ns - now + 999999) / 1000000;
        if (remaining < timeout) timeout = remaining;
    }
    uv_timer_start(&c->timer, on_timeout, timeout ? timeout : 1, 0);
}

static void allocate_read(uv_handle_t *handle, size_t suggested, uv_buf_t *buffer) {
    (void)handle;
    (void)suggested;
    buffer->base = (char *)malloc(8192);
    buffer->len = buffer->base ? 8192 : 0;
}

static void on_write(uv_write_t *request, int status) {
    queued_write *write = (queued_write *)request->data;
    connection *c = write->owner;
    uv_stream_t *source = write->source;
    int finish = write->finish;
    free(write->buffer.base);
    free(write);
    --c->pending;
    if (status < 0 || finish) {
        close_connection(c);
        return;
    }
    if ((c->asset_index >= 0 || c->static_entry) && c->pending == 0) {
        send_asset_chunk(c);
        return;
    }
    if (c->replaying && c->pending == 0) {
        send_replay_chunk(c);
        return;
    }
    if (!c->closed && source && c->pending < MAX_PENDING_WRITES) {
        uv_read_start(source, allocate_read,
                      source == (uv_stream_t *)&c->client ? on_client_read : on_upstream_read);
    }
}

static int queue_bytes(connection *c, uv_stream_t *destination,
                       uv_stream_t *source, const char *data, size_t length, int finish) {
    queued_write *write = (queued_write *)calloc(1, sizeof(*write));
    int result;
    if (!write || length > 65536) { free(write); return -1; }
    write->buffer.base = (char *)malloc(length ? length : 1);
    if (!write->buffer.base) { free(write); return -1; }
    memcpy(write->buffer.base, data, length);
    write->buffer.len = (unsigned int)length;
    write->owner = c;
    write->source = source;
    write->finish = finish;
    write->request.data = write;
    ++c->pending;
    result = uv_write(&write->request, destination, &write->buffer, 1, on_write);
    if (result < 0) {
        --c->pending;
        free(write->buffer.base);
        free(write);
        return -1;
    }
    if (source && c->pending >= MAX_PENDING_WRITES) uv_read_stop(source);
    return 0;
}

static void send_replay_chunk(connection *c) {
    size_t amount;
    if (c->replay_offset == c->replay_size) {
        free(c->replay_body);
        c->replay_body = NULL;
        c->replaying = 0;
        return;
    }
    amount = c->replay_size - c->replay_offset;
    if (amount > 32768) amount = 32768;
    if (queue_bytes(c, (uv_stream_t *)&c->upstream, NULL,
                    (const char *)c->replay_body + c->replay_offset, amount, 0) != 0)
        close_connection(c);
    else c->replay_offset += amount;
}

static void send_asset_chunk(connection *c) {
    const unsigned char *data;
    size_t size;
    size_t remaining, amount;
    if (c->closed) return;
    if (c->static_entry) {
        while (c->segment_index < c->segment_count &&
               c->segment_offset == c->segments[c->segment_index].size) {
            ++c->segment_index;
            c->segment_offset = 0;
        }
        if (c->segment_index == c->segment_count) {
            close_connection(c);
            return;
        }
        data = c->segments[c->segment_index].data;
        size = c->segments[c->segment_index].size;
        remaining = size - c->segment_offset;
        amount = remaining < 32768 ? remaining : 32768;
        c->segment_offset += amount;
        if (queue_bytes(c, (uv_stream_t *)&c->client, NULL,
                        (const char *)data + c->segment_offset - amount, amount,
                        c->segment_index + 1 == c->segment_count &&
                        c->segment_offset == size) != 0) close_connection(c);
        return;
    } else if (c->asset_index >= 0) {
        data = config.assets[c->asset_index].data;
        size = config.assets[c->asset_index].size;
    } else return;
    remaining = size - c->asset_offset;
    if (!remaining) { close_connection(c); return; }
    amount = remaining < 32768 ? remaining : 32768;
    c->asset_offset += amount;
    if (queue_bytes(c, (uv_stream_t *)&c->client, NULL,
                    (const char *)data + c->asset_offset - amount,
                    amount, c->asset_offset == size) != 0)
        close_connection(c);
}

static int asset_path(unsigned int index, char *out, size_t capacity) {
    const static_asset *asset = &config.assets[index];
    int length = snprintf(out, capacity, "/ankah/assets/%.*s/%s",
                          64, asset->etag + 1, asset->name);
    return length > 0 && (size_t)length < capacity ? 0 : -1;
}

static int not_modified_since(const char *input, const static_asset *asset) {
    static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    char weekday[4], month[4], zone[4];
    int day, year, hour, minute, second, month_number = -1, i;
    struct tm *modified;
    if (!input) return 0;
    if (sscanf(input, "%3[^,], %d %3s %d %d:%d:%d %3s",
               weekday, &day, month, &year, &hour, &minute, &second, zone) != 8 ||
        strcmp(zone, "GMT") != 0) return 0;
    for (i = 0; i < 12; ++i) if (strcmp(month, months[i]) == 0) month_number = i;
    if (month_number < 0 || day < 1 || day > 31 || hour < 0 || hour > 23 ||
        minute < 0 || minute > 59 || second < 0 || second > 60) return 0;
    modified = gmtime(&asset->modified);
    if (!modified) return 0;
    if (year != modified->tm_year + 1900) return year > modified->tm_year + 1900;
    if (month_number != modified->tm_mon) return month_number > modified->tm_mon;
    if (day != modified->tm_mday) return day > modified->tm_mday;
    if (hour != modified->tm_hour) return hour > modified->tm_hour;
    if (minute != modified->tm_min) return minute > modified->tm_min;
    return second >= modified->tm_sec;
}

static void serve_asset(connection *c) {
    char expected[160], response[1024];
    const static_asset *asset;
    const char *etag, *modified;
    unsigned int index;
    int length, cached;
    for (index = 0; index < ASSET_COUNT; ++index) {
        if (asset_path(index, expected, sizeof(expected)) == 0 &&
            strcmp(c->request.target, expected) == 0) break;
    }
    if (index == ASSET_COUNT) {
        respond(c, 404, "Not Found", "text/plain", "Unknown asset\n", NULL);
        return;
    }
    asset = &config.assets[index];
    etag = ankah_header_value(&c->request, "If-None-Match");
    modified = ankah_header_value(&c->request, "If-Modified-Since");
    cached = (etag && etag_matches(&c->request, asset->etag)) ||
             (!etag && not_modified_since(modified, asset));
    length = snprintf(response, sizeof(response),
                      "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                      "Content-Length: %zu\r\nCache-Control: public, max-age=31536000, immutable\r\n"
                      "ETag: %s\r\nLast-Modified: %s\r\n"
                      "X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
                      cached ? 304 : 200, cached ? "Not Modified" : "OK",
                      asset->type, asset->size,
                      asset->etag, asset->last_modified);
    if (length < 0 || (size_t)length >= sizeof(response)) { close_connection(c); return; }
    if (!cached && strcmp(c->request.method, "HEAD") != 0) c->asset_index = (int)index;
    if (queue_bytes(c, (uv_stream_t *)&c->client, NULL, response, (size_t)length,
                    c->asset_index < 0) != 0) close_connection(c);
}

static void cache_unlink(cache_blob *blob) {
    if (blob->previous) blob->previous->next = blob->next;
    else config.cache_first = blob->next;
    if (blob->next) blob->next->previous = blob->previous;
    else config.cache_last = blob->previous;
    blob->previous = blob->next = NULL;
}

static void cache_front(cache_blob *blob) {
    blob->next = config.cache_first;
    blob->previous = NULL;
    if (blob->next) blob->next->previous = blob;
    else config.cache_last = blob;
    config.cache_first = blob;
}

static cache_blob *cache_get(const ankah_static_variant *variant, int fill) {
    cache_blob *item, *previous;
    if (!config.static_cache_limit || !variant->size ||
        variant->size > config.static_cache_limit) return NULL;
    for (item = config.cache_first; item; item = item->next) {
        if (strcmp(item->etag, variant->etag) == 0) {
            cache_unlink(item);
            cache_front(item);
            ++item->pins;
            return item;
        }
    }
    if (!fill) return NULL;
    for (item = config.cache_last; item &&
         config.static_cache_used > config.static_cache_limit - variant->size;
         item = previous) {
        previous = item->previous;
        if (item->pins) continue;
        cache_unlink(item);
        config.static_cache_used -= item->size;
        free(item->data);
        free(item);
    }
    if (config.static_cache_used > config.static_cache_limit - variant->size)
        return NULL;
    item = calloc(1, sizeof(*item));
    if (!item) return NULL;
    item->data = malloc(variant->size);
    if (!item->data) { free(item); return NULL; }
    memcpy(item->data, variant->data, variant->size);
    item->size = variant->size;
    strcpy(item->etag, variant->etag);
    item->pins = 1;
    cache_front(item);
    config.static_cache_used += item->size;
    return item;
}

static int parse_quality(const char *start, const char **end) {
    const char *p = start;
    int value = 0, digits = 0, whole;
    if (*p != '0' && *p != '1') return -1;
    whole = *p++ - '0';
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9') {
            if (++digits > 3) return -1;
            value = value * 10 + (*p++ - '0');
        }
    }
    if (*p && *p != ',' && *p != ' ' && *p != '\t') return -1;
    if (whole && value) return -1;
    while (digits++ < 3) value *= 10;
    *end = p;
    return whole ? 1000 : value;
}

static int encoding_quality(const ankah_request *request, const char *name,
                            int identity) {
    int explicit_q = -1, wildcard_q = -1, found = 0;
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        const char *p, *end;
        if (!same_ascii(request->headers[i].name, "Accept-Encoding")) continue;
        found = 1;
        p = request->headers[i].value;
        while (*p) {
            const char *token, *token_end;
            int q = 1000;
            while (*p == ',' || *p == ' ' || *p == '\t') ++p;
            token = p;
            while (*p && *p != ',' && *p != ';' && *p != ' ' && *p != '\t') ++p;
            token_end = p;
            while (*p == ' ' || *p == '\t') ++p;
            if (*p == ';') {
                ++p;
                while (*p == ' ' || *p == '\t') ++p;
                if (strncasecmp(p, "q=", 2) != 0) q = 0;
                else {
                    p += 2;
                    q = parse_quality(p, &p);
                    if (q < 0) q = 0;
                }
            }
            while (*p && *p != ',') ++p;
            end = token_end;
            if ((size_t)(end - token) == strlen(name) &&
                strncasecmp(token, name, (size_t)(end - token)) == 0) explicit_q = q;
            if (end - token == 1 && *token == '*') wildcard_q = q;
        }
    }
    if (!found) return identity ? 1000 : 0;
    if (explicit_q >= 0) return explicit_q;
    if (identity) return wildcard_q == 0 ? 0 : 1000;
    return wildcard_q >= 0 ? wildcard_q : 0;
}

static int etag_matches(const ankah_request *request, const char *etag) {
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        const char *p;
        if (!same_ascii(request->headers[i].name, "If-None-Match")) continue;
        p = request->headers[i].value;
        while (*p) {
            const char *start, *end;
            while (*p == ' ' || *p == '\t' || *p == ',') ++p;
            start = p;
            while (*p && *p != ',') ++p;
            end = p;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
            if (end - start == 1 && *start == '*') return 1;
            if (end - start >= 2 && start[0] == 'W' && start[1] == '/') start += 2;
            if ((size_t)(end - start) == strlen(etag) &&
                strncmp(start, etag, (size_t)(end - start)) == 0) return 1;
        }
    }
    return 0;
}

typedef struct { size_t first, last; } byte_range;

static int parse_ranges(const char *value, size_t size, byte_range out[MAX_STATIC_RANGES]) {
    const char *p;
    int count = 0;
    if (!value || !starts_ascii(value, "bytes=")) return 0;
    p = value + 6;
    while (*p) {
        unsigned long long first = 0, last = 0;
        int suffix = 0, has_last = 0;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '-') suffix = 1;
        else {
            if (*p < '0' || *p > '9') return 0;
            while (*p >= '0' && *p <= '9') {
                unsigned int digit = (unsigned int)(*p++ - '0');
                if (first > (ULLONG_MAX - digit) / 10) return 0;
                first = first * 10 + digit;
            }
        }
        if (*p++ != '-') return 0;
        while (*p >= '0' && *p <= '9') {
            unsigned int digit = (unsigned int)(*p++ - '0');
            if (last > (ULLONG_MAX - digit) / 10) return 0;
            last = last * 10 + digit;
            has_last = 1;
        }
        if (suffix && !has_last) return 0;
        if (!suffix && has_last && last < first) return 0;
        if (++count > MAX_STATIC_RANGES) return 0;
        if (size && ((suffix && last) || (!suffix && first < size))) {
            byte_range *range = &out[count - 1];
            range->first = suffix ? (last >= size ? 0 : size - (size_t)last) : (size_t)first;
            range->last = suffix || !has_last || last >= size ? size - 1 : (size_t)last;
        } else out[count - 1].first = SIZE_MAX;
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        if (*p++ != ',' || !*p) return 0;
    }
    if (!count) return 0;
    {
        int i, j, kept = 0, merged = 0;
        for (i = 0; i < count; ++i)
            if (out[i].first != SIZE_MAX) out[kept++] = out[i];
        if (!kept) return -1;
        for (i = 1; i < kept; ++i) {
            byte_range item = out[i];
            j = i;
            while (j > 0 && (out[j - 1].first > item.first ||
                   (out[j - 1].first == item.first && out[j - 1].last > item.last))) {
                out[j] = out[j - 1];
                --j;
            }
            out[j] = item;
        }
        for (i = 0; i < kept; ++i) {
            if (merged && out[i].first <= out[merged - 1].last + 1) {
                if (out[i].last > out[merged - 1].last)
                    out[merged - 1].last = out[i].last;
            } else out[merged++] = out[i];
        }
        return merged;
    }
}

static int static_add_segment(connection *c, const unsigned char *data, size_t size) {
    if (c->segment_count == MAX_STATIC_SEGMENTS) return -1;
    c->segments[c->segment_count].data = data;
    c->segments[c->segment_count].size = size;
    ++c->segment_count;
    return 0;
}

static int static_add_text(connection *c, const char *text, size_t size) {
    unsigned char *destination;
    if (size > sizeof(c->segment_headers) - c->segment_headers_used) return -1;
    destination = (unsigned char *)c->segment_headers + c->segment_headers_used;
    memcpy(destination, text, size);
    c->segment_headers_used += size;
    return static_add_segment(c, destination, size);
}

static int serve_static_if_matched(connection *c) {
    char path[ANKAH_MAX_TARGET], response[1024], part[512], boundary[48];
    char content_type[256], range_field[128];
    const ankah_static_entry *entry;
    const ankah_static_variant *variant;
    const unsigned char *data;
    const char *query = strchr(c->request.target, '?');
    const char *range_header, *if_range, *encoding = NULL;
    byte_range ranges[MAX_STATIC_RANGES];
    size_t length = query ? (size_t)(query - c->request.target) :
                            strlen(c->request.target);
    size_t body_size;
    int cached, head, written, code = 200, range_count = 0, selected = -1;
    int best_quality = 0, i;
    if (!config.static_bundle.prefix || length >= sizeof(path)) return 0;
    memcpy(path, c->request.target, length);
    path[length] = 0;
    entry = ankah_static_find(&config.static_bundle, path);
    if (!entry) {
        if (!ankah_static_in_namespace(&config.static_bundle, path)) return 0;
        respond(c, 404, "Not Found", "text/plain", "Unknown static file\n", NULL);
        return 1;
    }
    head = strcmp(c->request.method, "HEAD") == 0;
    if (!head && strcmp(c->request.method, "GET") != 0) {
        respond(c, 405, "Method Not Allowed", "text/plain",
                "Method not allowed\n", "Allow: GET, HEAD\r\n");
        return 1;
    }
    for (i = 2; i >= 0; --i) {
        const char *name = i == 2 ? "br" : i == 1 ? "gzip" : "identity";
        int quality = encoding_quality(&c->request, name, i == 0);
        if (entry->variants[i].present && quality > best_quality) {
            selected = i;
            best_quality = quality;
        }
    }
    if (selected < 0) {
        if (head) {
            static const char unavailable[] =
                "HTTP/1.1 406 Not Acceptable\r\nContent-Type: text/plain\r\n"
                "Content-Length: 36\r\nVary: Accept-Encoding\r\n"
                "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                "Connection: close\r\n\r\n";
            if (queue_bytes(c, (uv_stream_t *)&c->client, NULL, unavailable,
                            sizeof(unavailable) - 1, 1) != 0) close_connection(c);
        } else respond(c, 406, "Not Acceptable", "text/plain",
                       "No acceptable static representation\n",
                       "Vary: Accept-Encoding\r\n");
        return 1;
    }
    variant = &entry->variants[selected];
    if (selected == 1) encoding = "gzip";
    if (selected == 2) encoding = "br";
    cached = etag_matches(&c->request, variant->etag);
    range_header = ankah_header_value(&c->request, "Range");
    if_range = ankah_header_value(&c->request, "If-Range");
    if (!cached && range_header && (!if_range || strcmp(if_range, variant->etag) == 0)) {
        range_count = parse_ranges(range_header, variant->size, ranges);
        if (range_count != 0) code = range_count < 0 ? 416 : 206;
    }
    body_size = code == 416 || cached ? 0 : variant->size;
    data = variant->data;
    if (code == 200 && !cached && !head && selected && variant->size) {
        c->cache_pin = cache_get(variant, 1);
        if (c->cache_pin) data = c->cache_pin->data;
    } else if (code == 206 && !head && selected) {
        c->cache_pin = cache_get(variant, 0);
        if (c->cache_pin) data = c->cache_pin->data;
    }
    if (code == 206 && range_count == 1) {
        body_size = ranges[0].last - ranges[0].first + 1;
        if (static_add_segment(c, data + ranges[0].first, body_size) != 0) goto failed;
    } else if (code == 206 && range_count > 1) {
        int n;
        body_size = 0;
        snprintf(boundary, sizeof(boundary), "ankah-%.*s", 32, variant->etag + 1);
        for (i = 0; i < range_count; ++i) {
            size_t piece = ranges[i].last - ranges[i].first + 1;
            n = snprintf(part, sizeof(part),
                         "--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zu-%zu/%zu\r\n\r\n",
                         boundary, entry->mime, ranges[i].first, ranges[i].last,
                         variant->size);
            if (n < 0 || (size_t)n >= sizeof(part) ||
                body_size > SIZE_MAX - (size_t)n - piece - 2 ||
                static_add_text(c, part, (size_t)n) != 0 ||
                static_add_segment(c, data + ranges[i].first, piece) != 0 ||
                static_add_text(c, "\r\n", 2) != 0) goto failed;
            body_size += (size_t)n + piece + 2;
        }
        n = snprintf(part, sizeof(part), "--%s--\r\n", boundary);
        if (n < 0 || (size_t)n >= sizeof(part) ||
            body_size > SIZE_MAX - (size_t)n ||
            static_add_text(c, part, (size_t)n) != 0) goto failed;
        body_size += (size_t)n;
    } else if (code == 200 && !cached && variant->size) {
        if (static_add_segment(c, data, variant->size) != 0) goto failed;
    }
    if (code == 206 && range_count > 1) {
        written = snprintf(content_type, sizeof(content_type),
                           "multipart/byteranges; boundary=%s", boundary);
    } else written = snprintf(content_type, sizeof(content_type), "%s", entry->mime);
    if (written < 0 || (size_t)written >= sizeof(content_type)) goto failed;
    range_field[0] = 0;
    if (code == 206 && range_count == 1) {
        written = snprintf(range_field, sizeof(range_field),
                           "Content-Range: bytes %zu-%zu/%zu\r\n",
                           ranges[0].first, ranges[0].last, variant->size);
    } else if (code == 416) {
        written = snprintf(range_field, sizeof(range_field),
                           "Content-Range: bytes */%zu\r\n", variant->size);
    } else written = 0;
    if (written < 0 || (size_t)written >= sizeof(range_field)) goto failed;
    written = snprintf(response, sizeof(response),
                       "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                       "Content-Length: %zu\r\nCache-Control: %s\r\n"
                       "ETag: %s\r\nVary: Accept-Encoding\r\nAccept-Ranges: bytes\r\n"
                       "X-Content-Type-Options: nosniff\r\n%s%sConnection: close\r\n\r\n",
                       cached ? 304 : code,
                       cached ? "Not Modified" : code == 206 ? "Partial Content" :
                       code == 416 ? "Range Not Satisfiable" : "OK",
                       content_type,
                       cached ? variant->size : body_size,
                       entry->immutable ? "public, max-age=31536000, immutable" :
                                          "public, max-age=60",
                       variant->etag,
                       encoding ? (selected == 1 ? "Content-Encoding: gzip\r\n" :
                                                   "Content-Encoding: br\r\n") : "",
                       range_field);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        goto failed;
    }
    if (!cached && code != 416 && !head && body_size) c->static_entry = entry;
    if (queue_bytes(c, (uv_stream_t *)&c->client, NULL, response, (size_t)written,
                    !c->static_entry) != 0) close_connection(c);
    return 1;
failed:
    close_connection(c);
    return 1;
}

static void respond(connection *c, int status, const char *reason,
                    const char *type, const char *body, const char *extra) {
    char response[16384];
    size_t body_size = strlen(body);
    int length = snprintf(response, sizeof(response),
                          "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                          "Content-Length: %zu\r\nCache-Control: no-store\r\n"
                          "X-Content-Type-Options: nosniff\r\n"
                          "Referrer-Policy: no-referrer\r\n"
                          "Connection: close\r\n%s\r\n%s",
                          status, reason, type, body_size, extra ? extra : "", body);
    if (length < 0 || (size_t)length >= sizeof(response) ||
        queue_bytes(c, (uv_stream_t *)&c->client, NULL, response, (size_t)length, 1) != 0)
        close_connection(c);
}

static int cookie_valid(const ankah_request *request) {
    const char *cookie = ankah_header_value(request, "Cookie");
    const char *item;
    char pass[ANKAH_PASS_TEXT_MAX];
    size_t length;
    if (!cookie) return 0;
    item = strstr(cookie, "ankah_pass=");
    if (!item || (item != cookie && item[-1] != ' ' && item[-1] != ';')) return 0;
    item += strlen("ankah_pass=");
    length = strcspn(item, "; \r\n");
    if (length == 0 || length >= sizeof(pass)) return 0;
    memcpy(pass, item, length);
    pass[length] = 0;
    return ankah_check_pass(config.secret, config.public_host,
                            (uint64_t)time(NULL), pass) == 0;
}

static int allowed(const ankah_request *request) {
    unsigned int i;
    ankah_session *session = request_session(request);
    if (ankah_session_solved(session, (uint64_t)time(NULL))) return 1;
    for (i = 0; i < config.allow_count; ++i) {
        if (prefix(request->target, config.allow[i])) return 1;
    }
    return cookie_valid(request);
}

static int parse_answer(const char *target, char *challenge, size_t capacity,
                        uint64_t *counter) {
    const char *start = strstr(target, "?challenge=");
    const char *answer;
    size_t length;
    if (!start) return -1;
    start += strlen("?challenge=");
    answer = strstr(start, "&answer=");
    if (!answer) return -1;
    length = (size_t)(answer - start);
    if (length == 0 || length >= capacity) return -1;
    memcpy(challenge, start, length);
    challenge[length] = 0;
    answer += strlen("&answer=");
    if (!*answer) return -1;
    return decimal_u64(answer, counter);
}

static int render_script(const char *challenge, char *out, size_t capacity) {
    const char *source = (const char *)config.assets[5].data;
    char solver_path[160], solver_url[512];
    const char *replacement;
    size_t used = 0, amount;
    int length;
    if (asset_path(4, solver_path, sizeof(solver_path)) != 0) return -1;
    length = snprintf(solver_url, sizeof(solver_url), "%s%s",
                      config.public_origin, solver_path);
    if (length < 0 || (size_t)length >= sizeof(solver_url)) return -1;
    while (*source) {
        amount = 1;
        replacement = source;
        if (prefix(source, "@ANKAH_SOLVER_URL@")) {
            replacement = solver_url;
            amount = strlen("@ANKAH_SOLVER_URL@");
        } else if (prefix(source, "@ANKAH_ORIGIN@")) {
            replacement = config.public_origin;
            amount = strlen("@ANKAH_ORIGIN@");
        } else if (prefix(source, "@ANKAH_CHALLENGE@")) {
            replacement = challenge;
            amount = strlen("@ANKAH_CHALLENGE@");
        }
        length = (int)(replacement == source ? 1 : strlen(replacement));
        if (length < 0 || (size_t)length >= capacity - used) return -1;
        memcpy(out + used, replacement, (size_t)length);
        used += (size_t)length;
        source += amount;
    }
    out[used] = 0;
    return 0;
}

static void render_gate(connection *c, ankah_session *session) {
    char body[8192], extra[512], action[ANKAH_MAX_TARGET * 6], hidden[128];
    char illustration[160], challenge_js[160];
    char worker_js[160] = "", wasm_path[160] = "";
    int n;
    if (asset_path(6, illustration, sizeof(illustration)) != 0 ||
        asset_path(3, challenge_js, sizeof(challenge_js)) != 0) {
        close_connection(c);
        return;
    }
#if ANKAH_HAS_WASM
    if (asset_path(7, worker_js, sizeof(worker_js)) != 0 ||
        asset_path(8, wasm_path, sizeof(wasm_path)) != 0) {
        close_connection(c); return;
    }
#endif
    if (session->is_post) {
        if (html_escape(session->target, action, sizeof(action)) != 0) {
            close_connection(c); return;
        }
        n = snprintf(hidden, sizeof(hidden),
                     "<input type=hidden name=ankah_continue value='%s'>", session->token);
    } else {
        n = snprintf(action, sizeof(action), "/ankah/finish/%s", session->id);
        hidden[0] = 0;
    }
    if (n < 0 || (size_t)n >= (session->is_post ? sizeof(hidden) : sizeof(action))) {
        close_connection(c); return;
    }
    n = snprintf(body, sizeof(body),
        "<!doctype html><html lang=en><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Checking your browser</title>"
        "<style>html,body{margin:0;min-height:100%%;font:16px system-ui;background:#101929;color:#f4f7fb}"
        "main{max-width:38rem;margin:5vh auto;padding:2rem;text-align:center;background:#18253b;border-radius:1rem}"
        "img{height:auto}#phone{width:100px}#qr{width:220px;background:white;padding:8px}"
        "#phone-help{display:flex;align-items:center;justify-content:center;gap:1rem;flex-wrap:wrap}"
        "button{padding:.7rem 1.5rem;font:inherit;cursor:pointer}"
        "</style><body data-challenge='%s' data-session='%s' data-worker='%s' data-wasm='%s'>"
        "<main><h1>Checking your browser</h1><p>Solving a short proof of work.</p>"
        "<output id=progress>Starting challenge...</output>"
        "<section id=phone-panel><h2>Don't have JavaScript? Scan here.</h2>"
        "<div id=phone-help><img id=phone src='%s' alt='Phone scanning a code'>"
        "<img id=qr src='/ankah/qr/%s.png' alt='QR code to solve on your phone'></div>"
        "<p>After solving on your phone, click Finished here.</p></section>"
        "<form id=finish method=%s action='%s'>%s<button type=submit>Finished</button></form>"
        "</main><script src='%s'></script></body></html>",
        session->challenge, session->id, worker_js, wasm_path,
        illustration, session->id,
        session->is_post ? "post" : "get",
        action, hidden,
        challenge_js);
    if (n < 0 || (size_t)n >= sizeof(body)) { close_connection(c); return; }
    n = snprintf(extra, sizeof(extra),
        "Set-Cookie: ankah_sid=%s; Max-Age=1800; Path=/; HttpOnly; SameSite=Lax%s\r\n"
        "Content-Security-Policy: default-src 'none'; img-src 'self'; "
        "script-src 'self' 'wasm-unsafe-eval'; "
        "worker-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'\r\n",
        session->id, prefix(config.public_origin, "https://") ? "; Secure" : "");
    if (n < 0 || (size_t)n >= sizeof(extra)) { close_connection(c); return; }
    respond(c, 428, "Precondition Required", "text/html; charset=utf-8", body, extra);
}

static void handle_challenge(connection *c) {
    char challenge[ANKAH_CHALLENGE_TEXT_MAX];
    char body[4096];
    char extra[512];
    const char *agent = ankah_header_value(&c->request, "User-Agent");
    int length;
    if (ankah_issue_challenge(config.secret, config.public_host,
                              (uint64_t)time(NULL), 18, challenge) != 0) {
        respond(c, 503, "Unavailable", "text/plain", "Challenge unavailable\n", NULL);
        return;
    }
    if (agent && (prefix(agent, "curl/") || prefix(agent, "Wget/"))) {
        length = snprintf(body, sizeof(body),
                          "Ankah challenge required.\n"
                          "Linux/macOS: curl -fsSL '%s/ankah/challenge/%s' | bash\n"
                          "Windows: curl.exe -fsSL -o ankah.cmd '%s/ankah/challenge/%s' && ankah.cmd\n",
                          config.public_origin, challenge, config.public_origin, challenge);
        if (length < 0 || (size_t)length >= sizeof(body)) { close_connection(c); return; }
        length = snprintf(extra, sizeof(extra),
                          "Location: /ankah/blocked/run-ankah-challenge-%s\r\n", challenge);
        if (length < 0 || (size_t)length >= sizeof(extra)) { close_connection(c); return; }
        respond(c, 302, "Found", "text/plain; charset=utf-8", body, extra);
    } else {
        if (strcmp(c->request.method, "GET") != 0 &&
            strcmp(c->request.method, "POST") != 0) {
            respond(c, 405, "Method Not Allowed", "text/plain",
                    "Unlock with a GET request, then retry this method.\n", NULL);
            return;
        }
        ankah_session *session = ankah_session_new(config.secret, config.public_host,
            (uint64_t)time(NULL), &c->request, c->peer_ip);
        size_t end = header_end(c->initial, c->initial_size);
        if (!session) {
            respond(c, 503, "Unavailable", "text/plain", "Challenge capacity reached\n", NULL);
            return;
        }
        if (session->is_post) {
            int complete = ankah_session_append(session, c->initial + end, c->initial_size - end);
            if (complete < 0) { ankah_session_discard(session); close_connection(c); return; }
            if (!complete) {
                c->capture_session = session;
                if (ankah_header_value(&c->request, "Expect") &&
                    same_ascii(ankah_header_value(&c->request, "Expect"), "100-continue")) {
                    static const char interim[] = "HTTP/1.1 100 Continue\r\n\r\n";
                    queue_bytes(c, (uv_stream_t *)&c->client, NULL, interim, sizeof(interim) - 1, 0);
                }
                return;
            }
        }
        render_gate(c, session);
    }
}

static void handle_internal(connection *c) {
    const char *target = c->request.target;
    const char *host = config.public_host;
    if (prefix(target, "/ankah/qr/") && strcmp(c->request.method, "GET") == 0) {
        const char *id = target + strlen("/ankah/qr/");
        char key[33], url[512];
        ankah_session *session;
        unsigned char *png;
        size_t size;
        if (strlen(id) != 36 || strcmp(id + 32, ".png") != 0) {
            respond(c, 404, "Not Found", "text/plain", "Unknown code\n", NULL); return;
        }
        memcpy(key, id, 32); key[32] = 0;
        session = ankah_session_find(key, (uint64_t)time(NULL));
        if (!session || snprintf(url, sizeof(url), "%s/ankah/solve/%s",
                                 config.public_origin, key) >= (int)sizeof(url) ||
            ankah_qr_png(url, &png, &size) != 0) {
            respond(c, 404, "Not Found", "text/plain", "Unknown code\n", NULL); return;
        }
        respond_binary(c, "image/png", png, size);
        free(png);
        return;
    }
    if (prefix(target, "/ankah/solve/") && strcmp(c->request.method, "GET") == 0) {
        ankah_session *session = ankah_session_find(target + strlen("/ankah/solve/"),
                                                    (uint64_t)time(NULL));
        char body[2048], script[160], worker_js[160] = "", wasm_path[160] = "";
        int n;
        if (!session || asset_path(3, script, sizeof(script)) != 0) {
            respond(c, 404, "Not Found", "text/plain", "Challenge expired\n", NULL); return;
        }
#if ANKAH_HAS_WASM
        if (asset_path(7, worker_js, sizeof(worker_js)) != 0 ||
            asset_path(8, wasm_path, sizeof(wasm_path)) != 0) {
            close_connection(c); return;
        }
#endif
        if (ankah_session_solved(session, (uint64_t)time(NULL))) {
            respond(c, 200, "OK", "text/html; charset=utf-8",
                    "<!doctype html><html lang=en><meta charset=utf-8><title>Finished</title>"
                    "<p>Challenge passed. Click Finished on the original page.</p>", NULL);
            return;
        }
        n = snprintf(body, sizeof(body),
            "<!doctype html><html lang=en><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Solve challenge</title><body data-challenge='%s' data-session='%s' "
            "data-worker='%s' data-wasm='%s' data-mobile=1>"
            "<main><h1>Solve challenge</h1><output id=progress>Starting...</output>"
            "<p>When complete, click Finished on the original page.</p></main>"
            "<script src='%s'></script></body></html>", session->challenge,
            session->id, worker_js, wasm_path, script);
        if (n < 0 || (size_t)n >= sizeof(body)) { close_connection(c); return; }
        respond(c, 200, "OK", "text/html; charset=utf-8", body,
                "Content-Security-Policy: default-src 'none'; "
                "script-src 'self' 'wasm-unsafe-eval'; "
                "worker-src 'self'; connect-src 'self'; frame-ancestors 'none'\r\n");
        return;
    }
    if (prefix(target, "/ankah/answer/") && strcmp(c->request.method, "POST") == 0) {
        const char *answer = strchr(target, '?');
        char key[33];
        uint64_t counter;
        ankah_session *session;
        if (!answer || (size_t)(answer - (target + strlen("/ankah/answer/"))) != 32 ||
            strncmp(answer, "?answer=", 8) != 0) {
            respond(c, 400, "Bad Request", "text/plain", "Invalid answer\n", NULL); return;
        }
        memcpy(key, target + strlen("/ankah/answer/"), 32); key[32] = 0;
        session = ankah_session_find(key, (uint64_t)time(NULL));
        if (decimal_u64(answer + 8, &counter) != 0 || !session ||
            ankah_check_answer(config.secret, host, (uint64_t)time(NULL),
                               session->challenge, counter) != 0 ||
            ankah_session_solve(session, (uint64_t)time(NULL)) != 0) {
            respond(c, 403, "Forbidden", "text/plain", "Invalid answer\n", NULL); return;
        }
        respond(c, 200, "OK", "text/plain", "Challenge passed. Click Finished on the original page.\n", NULL);
        return;
    }
    if (prefix(target, "/ankah/finish/") && strcmp(c->request.method, "GET") == 0) {
        ankah_session *session = ankah_session_find(target + strlen("/ankah/finish/"),
                                                    (uint64_t)time(NULL));
        char extra[sizeof(config.public_origin) + ANKAH_MAX_TARGET + 64];
        int n;
        if (!session || session != request_session(&c->request) || session->is_post ||
            !ankah_session_solved(session, (uint64_t)time(NULL))) {
            respond(c, 403, "Forbidden", "text/plain", "Challenge not passed\n", NULL); return;
        }
        if (session->target[1] == '/' || session->target[1] == '\\')
            n = snprintf(extra, sizeof(extra), "Location: %s%s\r\n",
                         config.public_origin, session->target);
        else
            n = snprintf(extra, sizeof(extra), "Location: %s\r\n", session->target);
        if (n < 0 || (size_t)n >= sizeof(extra)) { close_connection(c); return; }
        respond(c, 303, "See Other", "text/plain", "Continuing\n", extra);
        return;
    }
    if (prefix(target, "/ankah/assets/") &&
        (strcmp(c->request.method, "GET") == 0 ||
         strcmp(c->request.method, "HEAD") == 0)) {
        serve_asset(c);
        return;
    }
    if (prefix(target, "/ankah/challenge/") &&
        strcmp(c->request.method, "GET") == 0) {
        const char *challenge = target + strlen("/ankah/challenge/");
        char script[6144];
        if (strlen(challenge) >= ANKAH_CHALLENGE_TEXT_MAX ||
            strspn(challenge, "0123456789abcdef.") != strlen(challenge) ||
            render_script(challenge, script, sizeof(script)) != 0) {
            respond(c, 400, "Bad Request", "text/plain", "Invalid challenge\n", NULL);
            return;
        }
        respond(c, 200, "OK", "text/plain; charset=utf-8", script, NULL);
        return;
    }
    if (prefix(target, "/ankah/blocked/run-ankah-challenge-") &&
        strcmp(c->request.method, "GET") == 0) {
        const char *challenge = target + strlen("/ankah/blocked/run-ankah-challenge-");
        char body[2048];
        int length;
        if (strlen(challenge) >= ANKAH_CHALLENGE_TEXT_MAX ||
            strspn(challenge, "0123456789abcdef.") != strlen(challenge)) {
            respond(c, 400, "Bad Request", "text/plain", "Invalid challenge\n", NULL);
            return;
        }
        length = snprintf(body, sizeof(body),
                          "Ankah challenge required.\n"
                          "Linux/macOS: curl -fsSL '%s/ankah/challenge/%s' | bash\n"
                          "Windows: curl.exe -fsSL -o ankah.cmd '%s/ankah/challenge/%s' && ankah.cmd\n",
                          config.public_origin, challenge,
                          config.public_origin, challenge);
        if (length < 0 || (size_t)length >= sizeof(body)) { close_connection(c); return; }
        respond(c, 428, "Precondition Required", "text/plain; charset=utf-8", body, NULL);
        return;
    }
    if (prefix(target, "/ankah/open?") && strcmp(c->request.method, "POST") == 0) {
        char challenge[ANKAH_CHALLENGE_TEXT_MAX], pass[ANKAH_PASS_TEXT_MAX], header[256];
        uint64_t counter;
        int length;
        if (parse_answer(target, challenge, sizeof(challenge), &counter) != 0 ||
            ankah_check_answer(config.secret, host, (uint64_t)time(NULL), challenge, counter) != 0 ||
            ankah_issue_pass(config.secret, host, (uint64_t)time(NULL) + 43200, pass) != 0) {
            respond(c, 403, "Forbidden", "text/plain", "Invalid challenge answer\n", NULL);
            return;
        }
        length = snprintf(header, sizeof(header),
                          "Set-Cookie: ankah_pass=%s; Max-Age=43200; Path=/; HttpOnly; SameSite=Lax%s\r\n",
                          pass, prefix(config.public_origin, "https://") ? "; Secure" : "");
        if (length < 0 || (size_t)length >= sizeof(header)) { close_connection(c); return; }
        respond(c, 200, "OK", "text/plain", "Challenge passed. Retry your request.\n", header);
        return;
    }
    respond(c, 404, "Not Found", "text/plain", "Unknown Ankah endpoint\n", NULL);
}

static size_t header_end(const char *bytes, size_t length) {
    size_t i;
    for (i = 3; i < length; ++i) {
        if (bytes[i - 3] == '\r' && bytes[i - 2] == '\n' &&
            bytes[i - 1] == '\r' && bytes[i] == '\n') return i + 1;
    }
    return 0;
}

static int connection_names_header(const ankah_request *request, const char *name) {
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        const char *p;
        if (!same_ascii(request->headers[i].name, "Connection")) continue;
        p = request->headers[i].value;
        while (*p) {
            const char *start, *end;
            while (*p == ',' || *p == ' ' || *p == '\t') ++p;
            start = p;
            while (*p && *p != ',') ++p;
            end = p;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
            if (same_ascii_part(start, (size_t)(end - start), name)) return 1;
        }
    }
    return 0;
}

static int skip_upstream_header(const connection *c, const ankah_header *header) {
    if (same_ascii(header->name, "Host") ||
        same_ascii(header->name, "Content-Length")) return 0;
    if (c->websocket && same_ascii(header->name, "Upgrade")) return 0;
    if (same_ascii(header->name, "Connection") ||
        same_ascii(header->name, "Proxy-Connection") ||
        same_ascii(header->name, "Proxy-Authorization") ||
        same_ascii(header->name, "Keep-Alive") ||
        same_ascii(header->name, "TE") ||
        same_ascii(header->name, "Trailer") ||
        same_ascii(header->name, "Transfer-Encoding") ||
        same_ascii(header->name, "Upgrade") ||
        same_ascii(header->name, "Forwarded") ||
        same_ascii(header->name, "X-Real-IP") ||
        starts_ascii(header->name, "X-Forwarded-") ||
        (c->replaying && same_ascii(header->name, "Expect"))) return 1;
    return connection_names_header(&c->request, header->name);
}

static int build_upstream_request(const connection *c, char *out, size_t capacity) {
    size_t used = 0;
    unsigned int i;
    int length;
    length = snprintf(out, capacity, "%s %s HTTP/1.1\r\n",
                      c->request.method, c->request.target);
    if (length < 0 || (size_t)length >= capacity) return -1;
    used = (size_t)length;
    for (i = 0; i < c->request.count; ++i) {
        const ankah_header *header = &c->request.headers[i];
        if (skip_upstream_header(c, header)) continue;
        length = snprintf(out + used, capacity - used, "%s: %s\r\n",
                          header->name, header->value);
        if (length < 0 || (size_t)length >= capacity - used) return -1;
        used += (size_t)length;
    }
    length = snprintf(out + used, capacity - used,
                      "Connection: %s\r\nX-Forwarded-For: %s\r\n"
                      "X-Forwarded-Proto: %s\r\nX-Forwarded-Host: %s\r\n\r\n",
                      c->websocket ? "Upgrade" : "close", c->peer_ip,
                      config.public_https ? "https" : "http", config.public_host);
    if (length < 0 || (size_t)length >= capacity - used) return -1;
    return (int)(used + (size_t)length);
}

static void on_connected(uv_connect_t *request, int status) {
    connection *c = (connection *)request->data;
    char head[ANKAH_HEADER_LIMIT + 1024];
    size_t end;
    int head_size;
    if (status < 0 || c->closed) {
        if (!c->closed)
            respond(c, 502, "Bad Gateway", "text/plain", "Upstream unavailable\n", NULL);
        return;
    }
    head_size = build_upstream_request(c, head, sizeof(head));
    end = c->replaying ? 0 : header_end(c->initial, c->initial_size);
    if (head_size < 0 || (!c->replaying && end == 0) ||
        queue_bytes(c, (uv_stream_t *)&c->upstream, NULL, head, (size_t)head_size, 0) != 0 ||
        (!c->replaying && c->initial_size > end &&
         queue_bytes(c, (uv_stream_t *)&c->upstream, NULL,
                     c->initial + end, c->initial_size - end, 0) != 0)) {
        close_connection(c);
        return;
    }
    c->forwarding = 1;
    if (uv_read_start((uv_stream_t *)&c->upstream, allocate_read, on_upstream_read) != 0 ||
        (!c->replaying && uv_read_start((uv_stream_t *)&c->client,
                                      allocate_read, on_client_read) != 0))
        close_connection(c);
}

static int start_upstream(connection *c) {
    struct sockaddr_in address;
    int result;
    if (uv_ip4_addr(config.upstream_ip, config.upstream_port, &address) != 0) return -1;
    if (uv_tcp_init(config.loop, &c->upstream) != 0) return -1;
    c->upstream_initialized = 1;
    c->upstream.data = c;
    ++c->handles;
    c->connect_request.data = c;
    result = uv_tcp_connect(&c->connect_request, &c->upstream,
                            (const struct sockaddr *)&address, on_connected);
    return result;
}

static void finish_continue(connection *c) {
    ankah_session *session = request_session(&c->request);
    ankah_request *saved;
    unsigned char *body;
    size_t size;
    char token[33];
    if (c->continue_received != c->continue_expected ||
        c->continue_expected != 47 ||
        memcmp(c->continue_body, "ankah_continue=", 15) != 0) {
        respond(c, 403, "Forbidden", "text/plain", "Invalid continuation\n", NULL);
        return;
    }
    memcpy(token, c->continue_body + 15, 32);
    token[32] = 0;
    if (!session || strcmp(c->request.target, session->target) != 0 ||
        ankah_session_take_post(session, token, (uint64_t)time(NULL),
                                &saved, &body, &size) != 0) {
        respond(c, 403, "Forbidden", "text/plain", "Continuation expired\n", NULL);
        return;
    }
    c->request = *saved;
    free(saved);
    strcpy(c->peer_ip, session->peer_ip);
    c->replay_body = body;
    c->replay_size = size;
    c->replaying = 1;
    c->continue_expected = 0;
    uv_read_stop((uv_stream_t *)&c->client);
    if (start_upstream(c) != 0)
        respond(c, 502, "Bad Gateway", "text/plain", "Upstream unavailable\n", NULL);
}

static void handle_initial(connection *c) {
    size_t end = header_end(c->initial, c->initial_size);
    const char *expect;
    if (!end) {
        if (c->initial_size >= ANKAH_HEADER_LIMIT)
            respond(c, 431, "Request Header Fields Too Large", "text/plain",
                    "Request headers too large\n", NULL);
        return;
    }
    if (ankah_parse_request(c->initial, end, &c->request) != 0) {
        respond(c, 400, "Bad Request", "text/plain", "Invalid HTTP request\n", NULL);
        return;
    }
    {
        const char *request_host = ankah_header_value(&c->request, "Host");
        if (!same_ascii(request_host, config.public_host)) {
            respond(c, 421, "Misdirected Request", "text/plain",
                    "Unexpected Host\n", NULL);
            return;
        }
    }
    expect = ankah_header_value(&c->request, "Expect");
    if (expect && (!same_ascii(expect, "100-continue") || !c->request.has_body)) {
        respond(c, 417, "Expectation Failed", "text/plain",
                "Unsupported expectation\n", NULL);
        return;
    }
    c->websocket = c->request.websocket;
    if (c->request.chunked || c->request.content_length > MAX_BODY ||
        (!c->websocket && c->initial_size - end > c->request.content_length)) {
        respond(c, 413, "Content Too Large", "text/plain",
                "Unsupported request body. Unlock with a GET request, then retry.\n", NULL);
        return;
    }
    c->body_received = c->initial_size - end;
    c->request_deadline_ns = c->body_received < c->request.content_length ?
        uv_hrtime() + UINT64_C(120000000000) : 0;
    refresh_timeout(c);
    if (c->closed) return;
    if (strcmp(c->request.method, "POST") == 0) {
        ankah_session *session = request_session(&c->request);
        const char *type = ankah_header_value(&c->request, "Content-Type");
        if (session && session->is_post &&
            strcmp(c->request.target, session->target) == 0 &&
            ankah_session_solved(session, (uint64_t)time(NULL)) &&
            type && prefix(type, "application/x-www-form-urlencoded") &&
            c->request.content_length == 47) {
            c->capture_continue = 1;
            c->continue_expected = c->request.content_length;
            c->continue_received = c->body_received;
            memcpy(c->continue_body, c->initial + end, c->body_received);
            if (c->continue_received == c->continue_expected) finish_continue(c);
            return;
        }
    }
    if (prefix(c->request.target, "/ankah/")) {
        handle_internal(c);
    } else if (serve_static_if_matched(c)) {
        return;
    } else if (!allowed(&c->request)) {
        if (strcmp(c->request.method, "POST") == 0 &&
            c->request.content_length > ANKAH_POST_REPLAY_MAX) {
            respond(c, 413, "Content Too Large", "text/plain",
                    "Unlock with a small GET request, then retry this upload.\n", NULL);
            return;
        }
        handle_challenge(c);
    } else {
        uv_read_stop((uv_stream_t *)&c->client);
        if (start_upstream(c) != 0)
            respond(c, 502, "Bad Gateway", "text/plain", "Upstream unavailable\n", NULL);
    }
}

static void on_client_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer) {
    connection *c = (connection *)stream->data;
    if (count > 0 && !c->closed) {
        refresh_timeout(c);
        if (c->closed) { free(buffer->base); return; }
        if (c->capture_session) {
            int complete = ankah_session_append(c->capture_session, buffer->base, (size_t)count);
            if (complete < 0) {
                ankah_session_discard(c->capture_session);
                c->capture_session = NULL;
                respond(c, 400, "Bad Request", "text/plain", "Invalid body size\n", NULL);
            } else if (complete) {
                ankah_session *session = c->capture_session;
                c->capture_session = NULL;
                c->request_deadline_ns = 0;
                refresh_timeout(c);
                uv_read_stop(stream);
                render_gate(c, session);
            }
        } else if (c->capture_continue) {
            if ((size_t)count > c->continue_expected - c->continue_received) {
                respond(c, 400, "Bad Request", "text/plain", "Invalid continuation\n", NULL);
            } else {
                memcpy(c->continue_body + c->continue_received, buffer->base, (size_t)count);
                c->continue_received += (size_t)count;
                if (c->continue_received == c->continue_expected) {
                    c->request_deadline_ns = 0;
                    refresh_timeout(c);
                    finish_continue(c);
                }
            }
        } else if (!c->forwarding) {
            if ((size_t)count > ANKAH_HEADER_LIMIT - c->initial_size) {
                respond(c, 431, "Request Header Fields Too Large", "text/plain",
                        "Request headers too large\n", NULL);
            } else {
                memcpy(c->initial + c->initial_size, buffer->base, (size_t)count);
                c->initial_size += (size_t)count;
                handle_initial(c);
            }
        } else {
            if (!c->websocket) {
                if ((size_t)count > c->request.content_length - c->body_received) {
                    close_connection(c);
                    free(buffer->base);
                    return;
                }
                c->body_received += (size_t)count;
            }
            if (queue_bytes(c, (uv_stream_t *)&c->upstream, stream,
                            buffer->base, (size_t)count, 0) != 0) close_connection(c);
            if (!c->websocket && c->body_received == c->request.content_length) {
                c->request_deadline_ns = 0;
                refresh_timeout(c);
                uv_read_stop(stream);
            }
        }
    } else if (count < 0) {
        close_connection(c);
    }
    free(buffer->base);
}

static void on_upstream_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer) {
    connection *c = (connection *)stream->data;
    if (count > 0 && !c->closed) {
        refresh_timeout(c);
        if (c->closed) { free(buffer->base); return; }
        if (queue_bytes(c, (uv_stream_t *)&c->client, stream,
                        buffer->base, (size_t)count, 0) != 0) close_connection(c);
    } else if (count < 0) {
        close_connection(c);
    }
    free(buffer->base);
}

static void on_discard_closed(uv_handle_t *handle) {
    free(handle);
}

static void on_new_connection(uv_stream_t *server, int status) {
    connection *c;
    struct sockaddr_storage address;
    int address_size = sizeof(address);
    if (status < 0) return;
    if (config.connections >= MAX_CONNECTIONS) {
        uv_tcp_t *discard = (uv_tcp_t *)malloc(sizeof(*discard));
        if (discard && uv_tcp_init(config.loop, discard) == 0) {
            uv_accept(server, (uv_stream_t *)discard);
            uv_close((uv_handle_t *)discard, on_discard_closed);
        } else free(discard);
        return;
    }
    c = (connection *)calloc(1, sizeof(*c));
    if (!c) return;
    c->asset_index = -1;
    if (uv_tcp_init(config.loop, &c->client) != 0) { free(c); return; }
    c->client.data = c;
    c->handles = 1;
    ++config.connections;
    if (uv_accept(server, (uv_stream_t *)&c->client) != 0) {
        close_connection(c);
        return;
    }
    if (uv_timer_init(config.loop, &c->timer) != 0) {
        close_connection(c);
        return;
    }
    c->timer_initialized = 1;
    c->timer.data = c;
    ++c->handles;
    c->request_deadline_ns = uv_hrtime() + UINT64_C(30000000000);
    if (uv_tcp_getpeername(&c->client, (struct sockaddr *)&address, &address_size) == 0 &&
        address.ss_family == AF_INET) {
        uv_ip4_name((const struct sockaddr_in *)&address, c->peer_ip, sizeof(c->peer_ip));
    } else strcpy(c->peer_ip, "0.0.0.0");
    if (!allow_rate(c->peer_ip)) {
        respond(c, 429, "Too Many Requests", "text/plain",
                "Rate limit exceeded\n", "Retry-After: 1\r\n");
        return;
    }
    refresh_timeout(c);
    if (uv_read_start((uv_stream_t *)&c->client, allocate_read, on_client_read) != 0)
        close_connection(c);
}

static void on_child_exit(uv_process_t *process, int64_t status, int signal_number) {
    fprintf(stderr, "Ankah child exited: status=%" PRId64 " signal=%d\n",
            status, signal_number);
    uv_close((uv_handle_t *)process, NULL);
    uv_close((uv_handle_t *)&config.listener, NULL);
    uv_stop(config.loop);
}

int main(int argc, char **argv) {
    struct sockaddr_in address;
    uv_process_options_t child_options;
    int child_index, result;
    if (parse_options(argc, argv, &child_index) != 0) {
        fprintf(stderr, "usage: ankah --public-origin https://host --secret-file path "
                        "[--listen ip:port] [--upstream ip:port] "
                        "[--allow-prefix /path] [--static-bundle dir] [--static-cache-mb n] "
                        "[-- child command]\n");
        return 2;
    }
    config.loop = uv_default_loop();
    if (uv_ip4_addr(config.listen_ip, config.listen_port, &address) != 0 ||
        uv_tcp_init(config.loop, &config.listener) != 0 ||
        uv_tcp_bind(&config.listener, (const struct sockaddr *)&address, 0) != 0 ||
        uv_listen((uv_stream_t *)&config.listener, 128, on_new_connection) != 0) {
        fprintf(stderr, "Ankah failed to listen\n");
        return 1;
    }
    if (child_index < argc) {
        memset(&child_options, 0, sizeof(child_options));
        child_options.exit_cb = on_child_exit;
        child_options.file = argv[child_index];
        child_options.args = argv + child_index;
        result = uv_spawn(config.loop, &config.child, &child_options);
        if (result != 0) {
            fprintf(stderr, "Ankah failed to start child: %s\n", uv_strerror(result));
            return 1;
        }
        config.child_started = 1;
    }
    fprintf(stderr, "Ankah listening on %s:%d\n", config.listen_ip, config.listen_port);
    return uv_run(config.loop, UV_RUN_DEFAULT) == 0 ? 0 : 1;
}
