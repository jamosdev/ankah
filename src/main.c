#include "ankah/http.h"
#include "ankah/pow.h"
#include "ankah/static.h"
#include <uv.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <mbedtls/sha256.h>

#define MAX_CONNECTIONS 256
#define MAX_BODY (16U * 1024U * 1024U)
#define MAX_ALLOW 32
#define MAX_PENDING_WRITES 8
#define MAX_ASSET_SIZE (4U * 1024U * 1024U)
#define ASSET_COUNT 6
#define RATE_BUCKETS 1024

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
    unsigned int pending;
    unsigned int handles;
    int upstream_initialized;
    int timer_initialized;
    int forwarding;
    int closed;
    int websocket;
    int asset_index;
    const ankah_static_entry *static_entry;
    size_t asset_offset;
};

typedef struct {
    const char *name;
    const char *type;
    unsigned char *data;
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
    rate_bucket rates[RATE_BUCKETS];
    double global_tokens;
    uint64_t global_last_ns;
} configuration;

static configuration config;

static void close_connection(connection *c);
static void send_asset_chunk(connection *c);
static void respond(connection *c, int status, const char *reason,
                    const char *type, const char *body, const char *extra);
static void on_client_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer);
static void on_upstream_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer);

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

static int load_secret(const char *path) {
    char input[67];
    FILE *file = fopen(path, "rb");
    size_t size, i;
    if (!file) return -1;
    size = fread(input, 1, sizeof(input), file);
    fclose(file);
    if (size == 65 && input[64] == '\n') size = 64;
    if (size != 64) return -1;
    for (i = 0; i < ANKAH_SECRET_SIZE; ++i) {
        int high = hex_value(input[i * 2]);
        int low = hex_value(input[i * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        config.secret[i] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int load_asset(static_asset *asset, const char *directory) {
    static const char digits[] = "0123456789abcdef";
    struct stat metadata;
    unsigned char digest[32];
    char path[1024];
    FILE *file;
    size_t i;
    int length = snprintf(path, sizeof(path), "%s/%s", directory, asset->name);
    if (length < 0 || (size_t)length >= sizeof(path) ||
        stat(path, &metadata) != 0 || metadata.st_size < 0 ||
        (uint64_t)metadata.st_size > MAX_ASSET_SIZE) return -1;
    asset->size = (size_t)metadata.st_size;
    asset->modified = metadata.st_mtime;
    asset->data = (unsigned char *)malloc(asset->size + 1);
    if (!asset->data) return -1;
    file = fopen(path, "rb");
    if (!file) return -1;
    i = fread(asset->data, 1, asset->size, file);
    fclose(file);
    asset->data[asset->size] = 0;
    if (i != asset->size ||
        mbedtls_sha256_ret(asset->data, asset->size, digest, 0) != 0) return -1;
    asset->etag[0] = '"';
    for (i = 0; i < sizeof(digest); ++i) {
        asset->etag[1 + i * 2] = digits[digest[i] >> 4];
        asset->etag[2 + i * 2] = digits[digest[i] & 15];
    }
    asset->etag[65] = '"';
    asset->etag[66] = 0;
    if (!strftime(asset->last_modified, sizeof(asset->last_modified),
                  "%a, %d %b %Y %H:%M:%S GMT", gmtime(&asset->modified))) return -1;
    return 0;
}

static int load_assets(void) {
    static const char *names[ASSET_COUNT] = {
        "ankah.png", "particles.min.js", "particlejs.json", "challenge.js",
        "solver.py", "challenge-polyglot.txt"
    };
    static const char *types[ASSET_COUNT] = {
        "image/png", "application/javascript; charset=utf-8",
        "application/json; charset=utf-8", "application/javascript; charset=utf-8",
        "text/x-python; charset=utf-8", "text/plain; charset=utf-8"
    };
    unsigned int i;
    for (i = 0; i < ASSET_COUNT; ++i) {
        config.assets[i].name = names[i];
        config.assets[i].type = types[i];
        if (load_asset(&config.assets[i], config.assets_dir) != 0) return -1;
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

static int parse_options(int argc, char **argv, int *child_index) {
    int i;
    strcpy(config.listen_ip, "0.0.0.0");
    config.listen_port = 8000;
    strcpy(config.upstream_ip, "127.0.0.1");
    config.upstream_port = 8001;
    strcpy(config.assets_dir, ".");
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
        } else if (strcmp(argv[i], "--allow-prefix") == 0) {
            if (config.allow_count == MAX_ALLOW) return -1;
            config.allow[config.allow_count++] = argv[++i];
        } else return -1;
    }
    if (!prefix(config.public_origin, "https://") &&
        !prefix(config.public_origin, "http://")) return -1;
    {
        const char *host = strstr(config.public_origin, "://") + 3;
        if (!*host || strspn(host, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                  "0123456789.-:") != strlen(host)) return -1;
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
    uv_timer_start(&c->timer, on_timeout, c->websocket ? 300000 : 30000, 0);
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

static void send_asset_chunk(connection *c) {
    const unsigned char *data;
    size_t size;
    size_t remaining, amount;
    if (c->closed) return;
    if (c->static_entry) {
        data = c->static_entry->data;
        size = c->static_entry->size;
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
    cached = (etag && strcmp(etag, asset->etag) == 0) ||
             (!etag && not_modified_since(modified, asset));
    length = snprintf(response, sizeof(response),
                      "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                      "Content-Length: %zu\r\nCache-Control: public, max-age=31536000, immutable\r\n"
                      "ETag: %s\r\nLast-Modified: %s\r\nConnection: close\r\n\r\n",
                      cached ? 304 : 200, cached ? "Not Modified" : "OK",
                      asset->type, cached ? (size_t)0 : asset->size,
                      asset->etag, asset->last_modified);
    if (length < 0 || (size_t)length >= sizeof(response)) { close_connection(c); return; }
    if (!cached && strcmp(c->request.method, "HEAD") != 0) c->asset_index = (int)index;
    if (queue_bytes(c, (uv_stream_t *)&c->client, NULL, response, (size_t)length,
                    c->asset_index < 0) != 0) close_connection(c);
}

static int serve_static_if_matched(connection *c) {
    char path[ANKAH_MAX_TARGET], response[1024];
    const ankah_static_entry *entry;
    const char *query = strchr(c->request.target, '?');
    const char *conditional;
    size_t length = query ? (size_t)(query - c->request.target) :
                            strlen(c->request.target);
    int cached, head, written;
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
    conditional = ankah_header_value(&c->request, "If-None-Match");
    cached = conditional && strcmp(conditional, entry->etag) == 0;
    written = snprintf(response, sizeof(response),
                       "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                       "Content-Length: %zu\r\nCache-Control: %s\r\n"
                       "ETag: %s\r\nConnection: close\r\n\r\n",
                       cached ? 304 : 200, cached ? "Not Modified" : "OK",
                       entry->mime, cached ? (size_t)0 : entry->size,
                       entry->immutable ? "public, max-age=31536000, immutable" :
                                          "public, max-age=60",
                       entry->etag);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        close_connection(c);
        return 1;
    }
    if (!cached && !head && entry->size) c->static_entry = entry;
    if (queue_bytes(c, (uv_stream_t *)&c->client, NULL, response, (size_t)written,
                    !c->static_entry) != 0) close_connection(c);
    return 1;
}

static void respond(connection *c, int status, const char *reason,
                    const char *type, const char *body, const char *extra) {
    char response[8192];
    size_t body_size = strlen(body);
    int length = snprintf(response, sizeof(response),
                          "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                          "Content-Length: %zu\r\nCache-Control: no-store\r\n"
                          "Connection: close\r\n%s\r\n%s",
                          status, reason, type, body_size, extra ? extra : "", body);
    if (length < 0 || (size_t)length >= sizeof(response) ||
        queue_bytes(c, (uv_stream_t *)&c->client, NULL, response, (size_t)length, 1) != 0)
        close_connection(c);
}

static int cookie_valid(const ankah_request *request) {
    const char *cookie = ankah_header_value(request, "Cookie");
    const char *host = ankah_header_value(request, "Host");
    const char *item;
    char pass[ANKAH_PASS_TEXT_MAX];
    size_t length;
    if (!cookie || !host) return 0;
    item = strstr(cookie, "ankah_pass=");
    if (!item || (item != cookie && item[-1] != ' ' && item[-1] != ';')) return 0;
    item += strlen("ankah_pass=");
    length = strcspn(item, "; \r\n");
    if (length == 0 || length >= sizeof(pass)) return 0;
    memcpy(pass, item, length);
    pass[length] = 0;
    return ankah_check_pass(config.secret, host, (uint64_t)time(NULL), pass) == 0;
}

static int allowed(const ankah_request *request) {
    unsigned int i;
    if (request->websocket) return 1;
    for (i = 0; i < config.allow_count; ++i) {
        if (prefix(request->target, config.allow[i])) return 1;
    }
    return cookie_valid(request);
}

static int parse_answer(const char *target, char *challenge, size_t capacity,
                        uint64_t *counter) {
    const char *start = strstr(target, "?challenge=");
    const char *answer;
    char *end;
    unsigned long long value;
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
    value = strtoull(answer, &end, 10);
    if (*end || end == answer) return -1;
    *counter = (uint64_t)value;
    return 0;
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

static void handle_challenge(connection *c) {
    char challenge[ANKAH_CHALLENGE_TEXT_MAX];
    char body[4096];
    char extra[512];
    const char *host = ankah_header_value(&c->request, "Host");
    const char *agent = ankah_header_value(&c->request, "User-Agent");
    int length;
    if (ankah_issue_challenge(config.secret, host, (uint64_t)time(NULL), 18, challenge) != 0) {
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
        char mascot[160], particles_js[160], particles_json[160], challenge_js[160];
        if (asset_path(0, mascot, sizeof(mascot)) != 0 ||
            asset_path(1, particles_js, sizeof(particles_js)) != 0 ||
            asset_path(2, particles_json, sizeof(particles_json)) != 0 ||
            asset_path(3, challenge_js, sizeof(challenge_js)) != 0) {
            close_connection(c);
            return;
        }
        length = snprintf(body, sizeof(body),
                          "<!doctype html><html lang=en><meta charset=utf-8>"
                          "<meta name=viewport content='width=device-width,initial-scale=1'>"
                          "<title>Ankah challenge</title>"
                          "<style>html,body{margin:0;min-height:100%%;font:16px system-ui;background:#101929;color:#f4f7fb}"
                          "#particles-js{position:fixed;inset:0;z-index:0}main{position:relative;z-index:1;"
                          "max-width:35rem;margin:8vh auto;padding:2rem;text-align:center;"
                          "background:#18253be8;border-radius:1rem;box-shadow:0 1rem 3rem #0008}"
                          "img{width:min(14rem,45vw);height:auto}h1{margin:.5rem 0}"
                          "output{display:block;margin:1.5rem 0}</style>"
                          "<body data-challenge='%s' data-particles='%s'>"
                          "<div id=particles-js></div><main><img src='%s' alt='Ankah mascot'>"
                          "<h1>Checking your browser</h1>"
                          "<p>Solving a short proof of work to protect this service.</p>"
                          "<output id=progress>Starting challenge...</output>"
                          "<noscript>JavaScript is required for this challenge.</noscript></main>"
                          "<script src='%s'></script><script src='%s'></script></body></html>",
                          challenge, particles_json, mascot, particles_js, challenge_js);
        if (length < 0 || (size_t)length >= sizeof(body)) { close_connection(c); return; }
        respond(c, 428, "Precondition Required", "text/html; charset=utf-8", body,
                "Content-Security-Policy: default-src 'none'; img-src 'self'; "
                "script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'\r\n");
    }
}

static void handle_internal(connection *c) {
    const char *target = c->request.target;
    const char *host = ankah_header_value(&c->request, "Host");
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
    if (prefix(target, "/ankah/open") && strcmp(c->request.method, "POST") == 0) {
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
        if (same_ascii(header->name, "Connection") ||
            same_ascii(header->name, "Proxy-Connection") ||
            same_ascii(header->name, "X-Forwarded-For") ||
            same_ascii(header->name, "X-Real-IP") ||
            same_ascii(header->name, "Forwarded")) continue;
        length = snprintf(out + used, capacity - used, "%s: %s\r\n",
                          header->name, header->value);
        if (length < 0 || (size_t)length >= capacity - used) return -1;
        used += (size_t)length;
    }
    length = snprintf(out + used, capacity - used,
                      "Connection: %s\r\nX-Forwarded-For: %s\r\n\r\n",
                      c->websocket ? "Upgrade" : "close", c->peer_ip);
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
    end = header_end(c->initial, c->initial_size);
    if (head_size < 0 || end == 0 ||
        queue_bytes(c, (uv_stream_t *)&c->upstream, NULL, head, (size_t)head_size, 0) != 0 ||
        (c->initial_size > end &&
         queue_bytes(c, (uv_stream_t *)&c->upstream, NULL,
                     c->initial + end, c->initial_size - end, 0) != 0)) {
        close_connection(c);
        return;
    }
    c->forwarding = 1;
    if (uv_read_start((uv_stream_t *)&c->upstream, allocate_read, on_upstream_read) != 0 ||
        uv_read_start((uv_stream_t *)&c->client, allocate_read, on_client_read) != 0)
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

static void handle_initial(connection *c) {
    size_t end = header_end(c->initial, c->initial_size);
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
        const char *public_host = strstr(config.public_origin, "://") + 3;
        const char *request_host = ankah_header_value(&c->request, "Host");
        if (!same_ascii(request_host, public_host)) {
            respond(c, 421, "Misdirected Request", "text/plain",
                    "Unexpected Host\n", NULL);
            return;
        }
    }
    c->websocket = c->request.websocket;
    if (c->request.chunked || c->request.content_length > MAX_BODY ||
        (!c->websocket && c->initial_size - end > c->request.content_length)) {
        respond(c, 413, "Content Too Large", "text/plain",
                "Unsupported request body\n", NULL);
        return;
    }
    c->body_received = c->initial_size - end;
    if (prefix(c->request.target, "/ankah/")) {
        handle_internal(c);
    } else if (serve_static_if_matched(c)) {
        return;
    } else if (!allowed(&c->request)) {
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
        if (!c->forwarding) {
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
            if (!c->websocket && c->body_received == c->request.content_length)
                uv_read_stop(stream);
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
                        "[--allow-prefix /path] [--static-bundle dir] "
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
