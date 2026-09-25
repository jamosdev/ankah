/*
 * Copyright (C) 2026 Jamosdev
 *
 * This file is part of Ankah Core.
 *
 * Ankah Core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "ankah/http.h"
#include "ankah/language.h"
#include "ankah/files.h"
#include "ankah/frontend.h"
#include "ankah/h3_frontend.h"
#include "ankah/pow.h"
#include "ankah/proxy.h"
#include "ankah/static.h"
#include "ankah/session.h"
#include "ankah/qr.h"
#include "ankah/stats.h"
#include "header_names.h"
#include "language_internal.h"
#include "rate.h"
#include "timeout_policy.h"
#include "abuse_policy.h"
#include "dots.h"
#include "crawler.h"
#include <llhttp.h>
#include <uv.h>
#include <mbedtls/md.h>

#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ankah/sha256.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#if ANKAH_HAS_WASM
#include "browser_pow_data.h"
#endif

#define MAX_CONNECTIONS 256
#define MAX_DASHBOARD_CONNECTIONS 8
#define DASHBOARD_SESSIONS 32
#define DASHBOARD_SESSION_SECONDS (12U * 3600U)
#define LIVE_CACHE_NS UINT64_C(250000000)
#define STATS_SAVE_NS UINT64_C(900000000000)
#define TOP_CONNECTIONS 16
#define MAX_BODY (16U * 1024U * 1024U)
#define DEFAULT_MAX_UPLOAD_MB 1024U
#define MAX_UPLOAD_MB_LIMIT 1048576U
/* A forwarded body gets this long, and a body over MAX_BODY must then keep
 * up an average of UPLOAD_MIN_RATE bytes per second. */
#define UPLOAD_GRACE_NS UINT64_C(120000000000)
#define UPLOAD_MIN_RATE 65536U
#define UNLOCK_PATH "/ankah/unlock"
/* Leaves room for UNLOCK_PATH "?return=" so a generated link is itself a
 * valid request target. */
#define MAX_RETURN_PATH (ANKAH_MAX_TARGET - sizeof(UNLOCK_PATH "?return="))
#define MAX_ALLOW 32
#define MAX_PENDING_WRITES 8
#define MAX_ASSET_SIZE (4U * 1024U * 1024U)
#define ASSET_COUNT (8 + ANKAH_HAS_WASM)
#define DASHBOARD_ASSET_COUNT 4
#define ANONYMOUS_CONNECTIONS 192
#define PENDING_CONNECTIONS 32
#define MAX_STATIC_RANGES 16
#define MAX_STATIC_SEGMENTS (MAX_STATIC_RANGES * 3 + 1)
#define MAX_THROTTLE_PREFIXES 32
#define MAX_THROTTLE_CLIENTS 4096
#define MAX_THROTTLE_QUEUE 4096
#define MAX_THROTTLE_QUEUE_PER_CLIENT 64
#define MAX_THROTTLE_CONNECTIONS 224
#define CONFIG_FILE_MAX (1024U * 1024U)
#define CONFIG_LINE_MAX 4096U
#define CONFIG_PATH_MAX 4096U
#define THROTTLE_QUEUE_TTL_NS UINT64_C(15000000000)
#define THROTTLE_TICK_MS 1
#define THROTTLE_CHUNK 65536U
#define THROTTLE_BURST_NS UINT64_C(100000000)

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

typedef enum { RATE_ANONYMOUS, RATE_PROTECTED, RATE_CRAWLER, RATE_CLASSES } rate_class;

typedef struct {
    char *data;
    size_t size;
    unsigned int pins;
} shared_body;

typedef struct connection connection;
typedef struct throttle_client throttle_client;

typedef enum {
    LIFECYCLE_RUNNING,
    LIFECYCLE_DRAINING,
    LIFECYCLE_CHILD_STOPPING,
    LIFECYCLE_STOPPING
} lifecycle_state;

struct throttle_client {
    char id[ANKAH_CLIENT_ID_TEXT_SIZE];
    double tokens;
    uint64_t last_ns;
    unsigned int active, queued;
    connection *transfers, *cursor;
};

typedef struct {
    throttle_client *client;
    const ankah_static_entry *entry;
    uint64_t sequence, queued_ns, seen_ns;
    int active;
} throttle_queue_entry;

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
    uv_shutdown_t client_shutdown;
    uv_timer_t timer;
    llhttp_t upstream_response_parser;
    llhttp_settings_t upstream_response_settings;
    ankah_request request;
    ankah_chunked_body chunked_body;
    char initial[ANKAH_HEADER_LIMIT + 1];
    char peer_ip[64];
    char direct_peer_ip[64];
    int trusted_direct_peer;
    int abuse_action;
    int response_started;
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
    unsigned int pending_client;
    unsigned int pending_upstream;
    unsigned int handles;
    uint64_t request_deadline_ns;
    uint64_t reply_deadline_ns;
    int upstream_initialized;
    int timer_initialized;
    int forwarding;
    int closed;
    int response_finishing;
    int client_read_eof;
    int client_shutdown_done;
    int websocket;
    int internal;
    int rate_checked;
    int rate_class;
    int proved;
    int crawler;
    int crawler_slot;
    uint64_t external_crawler_slot_id;
    int bing_pending;
    int bing_checked;
    int initial_accounted;
    int initial_logged;
    int admission_state;
    int headers_handled;
    int large_body;
    uint64_t body_started_ns;
    int asset_index;
    const ankah_static_entry *static_entry;
    cache_blob *cache_pin;
    static_segment segments[MAX_STATIC_SEGMENTS];
    unsigned int segment_count, segment_index;
    size_t segment_offset;
    char segment_headers[8192];
    size_t segment_headers_used;
    size_t asset_offset;
    shared_body *body_pin;
    int segmented;
    int throttled;
    throttle_client *throttle_client;
    connection *throttle_previous, *throttle_next;
    connection *live_previous, *live_next;
    connection *all_previous, *all_next;
    int registered;
    int all_registered;
    int drain_tracked;
    int dashboard;
    int dashboard_api;
    int statistics_accepted;
    int status_seen;
    int upstream_final_started;
    uint64_t id;
    uint64_t accepted_ms;
    uint64_t upstream_started_ns;
    uint64_t bytes_in, tallied_bytes_in, bytes_out;
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
    int http3_enabled;
    int public_h3_port;
    char upstream_ip[64];
    int upstream_port;
    char public_origin[256];
    char public_host[256];
    int public_https;
    char secret_path[512];
    char assets_dir[512];
    char static_dir[512];
    char unknown_languages_path[512];
    char health_paths[3][ANKAH_MAX_TARGET];
    unsigned int health_seen;
    char tls_certificate[512];
    char tls_key[512];
    char internal_key[65];
    char allow[MAX_ALLOW][ANKAH_MAX_TARGET];
    unsigned int allow_count;
    char throttle_prefixes[MAX_THROTTLE_PREFIXES][ANKAH_MAX_TARGET];
    unsigned int throttle_prefix_count;
    unsigned int throttle_global_connections;
    unsigned int throttle_client_connections;
    uint64_t throttle_global_bytes_per_second;
    uint64_t throttle_client_bytes_per_second;
    unsigned int throttle_active, throttle_queue_count;
    throttle_client throttle_clients[MAX_THROTTLE_CLIENTS];
    throttle_queue_entry throttle_queue[MAX_THROTTLE_QUEUE];
    uint64_t throttle_sequence;
    double throttle_global_tokens;
    uint64_t throttle_global_last_ns;
    unsigned int throttle_client_cursor;
    uv_timer_t throttle_timer;
    int throttle_timer_initialized;
    int throttle_limit_seen;
    ankah_network trusted_proxies[ANKAH_MAX_TRUSTED_PROXIES];
    unsigned int trusted_proxy_count;
    ankah_abuse_policy *abuse_policy;
    unsigned char secret[ANKAH_SECRET_SIZE];
    uv_loop_t *loop;
    uv_tcp_t listener;
    uv_tcp_t internal_listener;
    int internal_listener_initialized;
    uv_process_t child;
    int child_started;
    int child_exited;
    int child_exit_code;
    lifecycle_state lifecycle;
    int intentional_shutdown;
    unsigned int active_requests;
#ifndef _WIN32
    uv_signal_t terminate_signal;
    uv_signal_t interrupt_signal;
    int terminate_signal_initialized;
    int interrupt_signal_initialized;
#endif
    unsigned int connections;
    unsigned int pending_connections;
    unsigned int anonymous_connections;
    static_asset assets[ASSET_COUNT];
    static_asset dashboard_assets[DASHBOARD_ASSET_COUNT];
    static_asset dashboard_pages[ANKAH_LANGUAGE_COUNT];
    ankah_static_bundle static_bundle;
    size_t static_cache_limit, static_cache_used;
    size_t max_upload;
    cache_blob *cache_first, *cache_last;
    rate_limit rate_limits[RATE_CLASSES];
    char dashboard_ip[64];
    int dashboard_port;
    int dashboard;
    char dashboard_public_route[ANKAH_MAX_TARGET];
    char dashboard_token_path[512];
    char stats_path[ANKAH_STATS_PATH_MAX];
    int stats_persistence_disabled;
    int stats_persistence_failed;
    uint64_t next_stats_save_ns;
    unsigned char dashboard_token[ANKAH_SECRET_SIZE];
    struct {
        unsigned char token[32];
        uint64_t expires;
    } dashboard_sessions[DASHBOARD_SESSIONS];
    uint64_t dashboard_last_code_step;
    uint64_t dashboard_attempt_window;
    unsigned int dashboard_failed_attempts;
    uv_tcp_t dashboard_listener;
    int dashboard_listener_initialized;
    uv_timer_t stats_timer;
    int stats_timer_initialized;
    unsigned int dashboard_connections;
    connection *live_first;
    connection *all_first;
    uint64_t next_connection_id;
    shared_body *live_body;
    uint64_t live_body_ns;
} configuration;

static configuration config;

static void close_connection(connection *c);
static void send_asset_chunk(connection *c);
static size_t send_asset_chunk_limit(connection *c, size_t limit);
static void handle_challenge(connection *c);
static void throttle_release(connection *c);
static void send_replay_chunk(connection *c);
static int queue_bytes(connection *c, uv_stream_t *destination,
                       uv_stream_t *source, const char *data, size_t length, int finish);
static void respond(connection *c, int status, const char *reason,
                    const char *type, const char *body, const char *extra);
static int etag_matches(const ankah_request *request, const char *etag);
static void on_client_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer);
static void on_upstream_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer);
static void allocate_read(uv_handle_t *handle, size_t suggested, uv_buf_t *buffer);
static void refresh_timeout(connection *c);
static size_t header_end(const char *bytes, size_t length);
static int save_stats(void);
static void maybe_finish_drain(void);
static void finish_shutdown(void);
static void handle_initial(connection *c);
static void release_crawler_slot(connection *c);
static void release_external_crawler_slot(connection *c);

/* Dashboard API traffic never reaches the statistics it reports. */
static void tally(const connection *c, unsigned int field, uint64_t amount) {
    if (!c->dashboard && !c->dashboard_api) ankah_stats_add(field, amount);
}

static void tally_max(const connection *c, unsigned int field, uint64_t value) {
    if (!c->dashboard && !c->dashboard_api) ankah_stats_max(field, value);
}

static void tally_client_bytes_in(connection *c) {
    if (c->bytes_in > c->tallied_bytes_in) {
        tally(c, ANKAH_STAT_client_bytes_in, c->bytes_in - c->tallied_bytes_in);
        c->tallied_bytes_in = c->bytes_in;
    }
}

static void tally_status(const connection *c, int status) {
    static const unsigned int classes[4] = {
        ANKAH_STAT_responses_2xx, ANKAH_STAT_responses_3xx,
        ANKAH_STAT_responses_4xx, ANKAH_STAT_responses_5xx
    };
    if (status >= 200 && status <= 599) tally(c, classes[status / 100 - 2], 1);
}

static void body_release(shared_body *body) {
    if (body && --body->pins == 0) {
        free(body->data);
        free(body);
    }
}

static void registry_link(connection *c) {
    c->live_previous = NULL;
    c->live_next = config.live_first;
    if (c->live_next) c->live_next->live_previous = c;
    config.live_first = c;
    c->registered = 1;
}

static void registry_unlink(connection *c) {
    if (!c->registered) return;
    if (c->live_previous) c->live_previous->live_next = c->live_next;
    else config.live_first = c->live_next;
    if (c->live_next) c->live_next->live_previous = c->live_previous;
    c->live_previous = c->live_next = NULL;
    c->registered = 0;
}

static void account_public_connection(connection *c) {
    if (!config.dashboard || c->dashboard || c->dashboard_api || c->statistics_accepted)
        return;
    c->statistics_accepted = 1;
    ankah_stats_roll((uint64_t)time(NULL));
    ankah_stats_add(ANKAH_STAT_accepted, 1);
    ankah_stats_max(ANKAH_STAT_peak_connections, config.connections);
}

static void all_link(connection *c) {
    c->all_previous = NULL;
    c->all_next = config.all_first;
    if (c->all_next) c->all_next->all_previous = c;
    config.all_first = c;
    c->all_registered = 1;
}

static void all_unlink(connection *c) {
    if (!c->all_registered) return;
    if (c->all_previous) c->all_previous->all_next = c->all_next;
    else config.all_first = c->all_next;
    if (c->all_next) c->all_next->all_previous = c->all_previous;
    c->all_previous = c->all_next = NULL;
    c->all_registered = 0;
}

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

static int contains_ascii(const char *value, const char *part) {
    size_t length = strlen(part);
    while (*value) {
        if (same_ascii_part(value, length, part)) return 1;
        ++value;
    }
    return 0;
}

static void respond_binary(connection *c, const char *type,
                           const unsigned char *body, size_t size) {
    char head[512];
    tally_status(c, 200);
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

/* A return path is written verbatim into a Location header, so it must be a
 * local path of visible ASCII that no browser can read as another host. */
static int valid_return_path(const char *path) {
    size_t length = strlen(path), i;
    if (length == 0 || length > MAX_RETURN_PATH || path[0] != '/' ||
        path[1] == '/' || path[1] == '\\') return 0;
    for (i = 0; i < length; ++i) {
        unsigned char byte = (unsigned char)path[i];
        if (byte < 0x21 || byte > 0x7e) return 0;
    }
    return 1;
}

static void referer_return_path(const ankah_request *request, char *out, size_t capacity) {
    const char *referer = ankah_header_value(request, "Referer");
    size_t origin = strlen(config.public_origin);
    const char *path;
    strcpy(out, "/");
    if (!referer || !starts_ascii(referer, config.public_origin) ||
        referer[origin] != '/') return;
    path = referer + origin;
    if (valid_return_path(path) && strlen(path) < capacity) strcpy(out, path);
}

static int unlock_url(const char *return_path, char *out, size_t capacity) {
    int length = strcmp(return_path, "/") == 0 ?
        snprintf(out, capacity, "%s" UNLOCK_PATH, config.public_origin) :
        snprintf(out, capacity, "%s" UNLOCK_PATH "?return=%s",
                 config.public_origin, return_path);
    return length < 0 || (size_t)length >= capacity ? -1 : 0;
}

static int allow_rate(rate_class kind, const char *ip) {
    rate_limit *limit = &config.rate_limits[kind];
    double global_burst = kind == RATE_PROTECTED ? 1000.0 :
                          kind == RATE_CRAWLER ? 10.0 : 200.0;
    double global_refill = kind == RATE_PROTECTED ? 500.0 :
                           kind == RATE_CRAWLER ? 2.0 : 100.0;
    double client_burst = kind == RATE_PROTECTED ? 200.0 :
                          kind == RATE_CRAWLER ? 10.0 : 40.0;
    double client_refill = kind == RATE_PROTECTED ? 100.0 :
                           kind == RATE_CRAWLER ? 2.0 : 20.0;
    return ankah_rate_allow(limit, ip, uv_hrtime(), global_burst, global_refill,
                            client_burst, client_refill);
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

static int load_hex_file(const char *path, unsigned char out[ANKAH_SECRET_SIZE]) {
    unsigned char *input = NULL;
    size_t size = 0, i;
    if (ankah_file_read(path, 65, 1, &input, &size, NULL) != 0 ||
        (size != 64 && size != 65)) {
        free(input);
        return -1;
    }
    if (size == 65 && input[64] == '\n') size = 64;
    if (size != 64) { erase_bytes(input, 65); free(input); return -1; }
    for (i = 0; i < ANKAH_SECRET_SIZE; ++i) {
        int high = hex_value(input[i * 2]);
        int low = hex_value(input[i * 2 + 1]);
        if (high < 0 || low < 0) {
            erase_bytes(input, 65);
            free(input);
            erase_bytes(out, ANKAH_SECRET_SIZE);
            return -1;
        }
        out[i] = (unsigned char)((high << 4) | low);
    }
    erase_bytes(input, 65);
    free(input);
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
    char path[1024];
    unsigned char *data;
    int length = snprintf(path, sizeof(path), "%s/%s", directory, asset->name);
    if (length < 0 || (size_t)length >= sizeof(path) ||
        ankah_file_read(path, MAX_ASSET_SIZE, 0, &data,
                        &asset->size, &asset->modified) != 0) return -1;
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

/* Loaded only when the dashboard is enabled, and never served by the public
 * listener because serve_asset looks only at the first ASSET_COUNT files. */
static int load_dashboard_assets(void) {
    static const char *names[DASHBOARD_ASSET_COUNT] = {
        "dashboard/index.html", "dashboard/dashboard.css", "dashboard/dashboard.js",
        "dashboard/d3-subset.min.js"
    };
    static const char *types[DASHBOARD_ASSET_COUNT] = {
        "text/html; charset=utf-8", "text/css; charset=utf-8",
        "application/javascript; charset=utf-8", "application/javascript; charset=utf-8"
    };
    unsigned int i;
    for (i = 0; i < DASHBOARD_ASSET_COUNT; ++i) {
        config.dashboard_assets[i].name = names[i];
        config.dashboard_assets[i].type = types[i];
        if (load_asset(&config.dashboard_assets[i], config.assets_dir) != 0) return -1;
    }
    for (i = 0; i < ANKAH_LANGUAGE_COUNT; ++i) {
        static_asset *page = &config.dashboard_pages[i];
        const static_asset *source = &config.dashboard_assets[0];
        unsigned char *rendered;
        page->name = source->name;
        page->type = source->type;
        page->modified = source->modified;
        if (ankah_language_render_html((ankah_language)i, source->data, source->size,
                NULL, MAX_ASSET_SIZE, &page->size, ankah_language_text) != 0)
            return -1;
        rendered = malloc(page->size ? page->size : 1);
        if (!rendered || ankah_language_render_html((ankah_language)i,
                source->data, source->size, rendered, page->size,
                &page->size, ankah_language_text) != 0) {
            free(rendered);
            return -1;
        }
        page->data = rendered;
        if (finish_asset(page) != 0) return -1;
    }
    free((void *)config.dashboard_assets[0].data);
    config.dashboard_assets[0].data = NULL;
    config.dashboard_assets[0].size = 0;
    return 0;
}

static int parse_address(const char *input, char *ip, size_t capacity, int *port) {
    const char *colon, *address_start = input, *address_end;
    char *end;
    long value;
    size_t length;
    if (input[0] == '[') {
        address_start = input + 1;
        address_end = strchr(address_start, ']');
        if (!address_end || address_end[1] != ':') return -1;
        colon = address_end + 1;
    } else {
        colon = strrchr(input, ':');
        if (!colon || memchr(input, ':', (size_t)(colon - input))) return -1;
        address_end = colon;
    }
    length = (size_t)(address_end - address_start);
    if (length == 0 || length >= capacity) return -1;
    memcpy(ip, address_start, length);
    ip[length] = 0;
    value = strtol(colon + 1, &end, 10);
    if (*end || value < 1 || value > 65535) return -1;
    *port = (int)value;
    return 0;
}

static int socket_address(const char *ip, int port, struct sockaddr_storage *out) {
    memset(out, 0, sizeof(*out));
    if (strchr(ip, ':'))
        return uv_ip6_addr(ip, port, (struct sockaddr_in6 *)out);
    return uv_ip4_addr(ip, port, (struct sockaddr_in *)out);
}

static void hex_encode(const unsigned char *input, size_t size, char *out) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < size; ++i) {
        out[i * 2] = digits[input[i] >> 4];
        out[i * 2 + 1] = digits[input[i] & 15];
    }
    out[size * 2] = 0;
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

static int valid_throttle_prefix(const char *value) {
    size_t i, length;
    if (!value || value[0] != '/') return 0;
    length = strlen(value);
    if (!length || length >= ANKAH_MAX_TARGET || value[length - 1] != '/') return 0;
    for (i = 0; i < length; ++i)
        if ((unsigned char)value[i] < 33 || (unsigned char)value[i] > 126 ||
            value[i] == '?' || value[i] == '#' || value[i] == '%' ||
            value[i] == '\\' || (i && value[i] == '/' && value[i - 1] == '/'))
            return 0;
    return strncmp(value, "/ankah/", 7) != 0;
}

static int valid_dashboard_public_route(const char *value) {
    size_t i, length;
    if (!value || value[0] != '/') return 0;
    length = strlen(value);
    if (length <= 1 || length >= ANKAH_MAX_TARGET || value[length - 1] != '/') return 0;
    for (i = 0; i < length; ++i)
        if ((unsigned char)value[i] < 33 || (unsigned char)value[i] > 126 ||
            value[i] == '?' || value[i] == '#' || value[i] == '%' ||
            value[i] == '\\' || (i && value[i] == '/' && value[i - 1] == '/'))
            return 0;
    return strncmp(value, "/ankah/", 7) != 0;
}

typedef enum {
    OPTION_SOURCE_CONFIG = 1,
    OPTION_SOURCE_ENVIRONMENT = 2,
    OPTION_SOURCE_COMMAND_LINE = 3
} option_source;

typedef struct {
    option_source source;
    const char *label;
    unsigned int line;
    const char *base_directory;
} option_context;

typedef struct {
    unsigned char health[3];
    unsigned char stats_file;
    unsigned char no_stats_file;
    unsigned char unknown_languages;
} option_state;

static int ascii_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
           c == '\f' || c == '\v';
}

static int canonical_path(const char *input, const char *base,
                          char *out, size_t capacity) {
    char combined[CONFIG_PATH_MAX * 2];
    const char *candidate = input;
    int length;
    if (!input || !input[0]) {
        if (capacity) out[0] = 0;
        return capacity ? 0 : -1;
    }
#ifdef _WIN32
    if (base && !((input[0] == '/' || input[0] == '\\') ||
                  (input[0] && input[1] == ':' &&
                   (input[2] == '/' || input[2] == '\\')))) {
        length = snprintf(combined, sizeof(combined), "%s\\%s", base, input);
        if (length < 0 || (size_t)length >= sizeof(combined)) return -1;
        candidate = combined;
    }
    {
        DWORD size = GetFullPathNameA(candidate, (DWORD)capacity, out, NULL);
        return size && size < capacity ? 0 : -1;
    }
#else
    if (input[0] != '/') {
        char current[CONFIG_PATH_MAX];
        const char *directory = base;
        size_t current_size = sizeof(current);
        if (!directory) {
            if (uv_cwd(current, &current_size) != 0) return -1;
            directory = current;
        }
        length = snprintf(combined, sizeof(combined), "%s/%s", directory, input);
        if (length < 0 || (size_t)length >= sizeof(combined)) return -1;
        candidate = combined;
    }
    {
        const char *at = candidate;
        size_t used = 1;
        if (capacity < 2 || candidate[0] != '/') return -1;
        out[0] = '/';
        while (*at) {
            const char *start;
            size_t size;
            while (*at == '/') ++at;
            if (!*at) break;
            start = at;
            while (*at && *at != '/') ++at;
            size = (size_t)(at - start);
            if (size == 1 && start[0] == '.') continue;
            if (size == 2 && start[0] == '.' && start[1] == '.') {
                while (used > 1 && out[used - 1] != '/') --used;
                if (used > 1) --used;
                continue;
            }
            if (used > 1) {
                if (used + 1 >= capacity) return -1;
                out[used++] = '/';
            }
            if (size >= capacity - used) return -1;
            memcpy(out + used, start, size);
            used += size;
        }
        out[used] = 0;
    }
    return 0;
#endif
}

static int path_directory(const char *path, char *out, size_t capacity) {
    char *last, *backslash;
    size_t size = strlen(path);
    if (size >= capacity) return -1;
    memcpy(out, path, size + 1);
    last = strrchr(out, '/');
    backslash = strrchr(out, '\\');
    if (backslash && (!last || backslash > last)) last = backslash;
    if (!last) return -1;
    if (last == out) last[1] = 0;
#ifdef _WIN32
    else if (last == out + 2 && out[1] == ':') last[1] = 0;
#endif
    else *last = 0;
    return 0;
}

static int copy_text(char *out, size_t capacity, const char *value) {
    size_t size = strlen(value);
    if (size >= capacity) return -1;
    memcpy(out, value, size + 1);
    return 0;
}

static int copy_path(char *out, size_t capacity, const char *value,
                     const option_context *context) {
    if (context->source == OPTION_SOURCE_CONFIG)
        return canonical_path(value, context->base_directory, out, capacity);
    return copy_text(out, capacity, value);
}

static int boolean_value(const char *value, int *out) {
    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) *out = 1;
    else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) *out = 0;
    else return -1;
    return 0;
}

static int health_name(const char *name) {
    static const char *const names[3] = {
        "ankah-healthz", "ankah-livez", "ankah-readyz"
    };
    unsigned int i;
    for (i = 0; i < 3; ++i)
        if (strcmp(name, names[i]) == 0) return (int)i;
    return -1;
}

static int apply_option(const char *name, const char *value,
                        const option_context *context, option_state *state) {
    int health = health_name(name);
    if (health >= 0) {
        size_t size = strlen(value);
        if (state->health[health] == context->source || !size || value[0] != '/' ||
            size >= sizeof(config.health_paths[health]) ||
            strchr(value, '?') || strchr(value, '#')) return -1;
        memcpy(config.health_paths[health], value, size + 1);
        config.health_seen |= 1U << health;
        state->health[health] = (unsigned char)context->source;
    } else if (strcmp(name, "listen") == 0) {
        if (parse_address(value, config.listen_ip, sizeof(config.listen_ip),
                          &config.listen_port) != 0) return -1;
    } else if (strcmp(name, "upstream") == 0) {
        if (parse_address(value, config.upstream_ip, sizeof(config.upstream_ip),
                          &config.upstream_port) != 0) return -1;
    } else if (strcmp(name, "public-origin") == 0) {
        if (copy_text(config.public_origin, sizeof(config.public_origin), value) != 0) return -1;
    } else if (strcmp(name, "secret-file") == 0) {
        if (copy_path(config.secret_path, sizeof(config.secret_path), value, context) != 0)
            return -1;
    } else if (strcmp(name, "assets-dir") == 0) {
        if (copy_path(config.assets_dir, sizeof(config.assets_dir), value, context) != 0)
            return -1;
    } else if (strcmp(name, "static-bundle") == 0) {
        if (copy_path(config.static_dir, sizeof(config.static_dir), value, context) != 0)
            return -1;
    } else if (strcmp(name, "static-cache-mb") == 0) {
        uint64_t megabytes;
        if (decimal_u64(value, &megabytes) != 0 ||
            megabytes > SIZE_MAX / (1024U * 1024U)) return -1;
        config.static_cache_limit = (size_t)megabytes * 1024U * 1024U;
    } else if (strcmp(name, "max-upload-mb") == 0) {
        uint64_t megabytes;
        if (decimal_u64(value, &megabytes) != 0 ||
            (megabytes != 0 && megabytes < MAX_BODY / (1024U * 1024U)) ||
            megabytes > MAX_UPLOAD_MB_LIMIT ||
            megabytes > SIZE_MAX / (1024U * 1024U)) return -1;
        config.max_upload = (size_t)megabytes * 1024U * 1024U;
    } else if (strcmp(name, "static-throttle-prefix") == 0) {
        unsigned int i;
        if (config.throttle_prefix_count == MAX_THROTTLE_PREFIXES ||
            !valid_throttle_prefix(value)) return -1;
        for (i = 0; i < config.throttle_prefix_count; ++i)
            if (strcmp(config.throttle_prefixes[i], value) == 0) return -1;
        strcpy(config.throttle_prefixes[config.throttle_prefix_count++], value);
    } else if (strcmp(name, "static-throttle-global-connections") == 0 ||
               strcmp(name, "static-throttle-client-connections") == 0) {
        uint64_t amount;
        if (decimal_u64(value, &amount) != 0 || !amount ||
            amount > MAX_THROTTLE_CONNECTIONS) return -1;
        if (strcmp(name, "static-throttle-global-connections") == 0)
            config.throttle_global_connections = (unsigned int)amount;
        else config.throttle_client_connections = (unsigned int)amount;
        config.throttle_limit_seen = 1;
    } else if (strcmp(name, "static-throttle-global-mbps") == 0 ||
               strcmp(name, "static-throttle-client-mbps") == 0) {
        uint64_t amount;
        if (decimal_u64(value, &amount) != 0 || !amount ||
            amount > UINT64_MAX / UINT64_C(125000)) return -1;
        if (strcmp(name, "static-throttle-global-mbps") == 0)
            config.throttle_global_bytes_per_second = amount * UINT64_C(125000);
        else config.throttle_client_bytes_per_second = amount * UINT64_C(125000);
        config.throttle_limit_seen = 1;
    } else if (strcmp(name, "tls-cert") == 0) {
        if (copy_path(config.tls_certificate, sizeof(config.tls_certificate),
                      value, context) != 0) return -1;
    } else if (strcmp(name, "tls-key") == 0) {
        if (copy_path(config.tls_key, sizeof(config.tls_key), value, context) != 0) return -1;
    } else if (strcmp(name, "http3") == 0) {
        if (strcmp(value, "on") == 0) config.http3_enabled = 1;
        else if (strcmp(value, "off") == 0) config.http3_enabled = 0;
        else return -1;
    } else if (strcmp(name, "proxy-abuse-profile") == 0) {
        if (strcmp(value, "off") == 0)
            ankah_abuse_set_profile(config.abuse_policy, ANKAH_ABUSE_OFF);
        else if (strcmp(value, "conservative") == 0)
            ankah_abuse_set_profile(config.abuse_policy, ANKAH_ABUSE_CONSERVATIVE);
        else if (strcmp(value, "strict") == 0)
            ankah_abuse_set_profile(config.abuse_policy, ANKAH_ABUSE_STRICT);
        else return -1;
    } else if (strcmp(name, "trusted-proxy") == 0) {
        if (config.trusted_proxy_count == ANKAH_MAX_TRUSTED_PROXIES ||
            ankah_parse_network(value,
                                &config.trusted_proxies[config.trusted_proxy_count]) != 0)
            return -1;
        ++config.trusted_proxy_count;
    } else if (strcmp(name, "dashboard-listen") == 0) {
        if (parse_address(value, config.dashboard_ip, sizeof(config.dashboard_ip),
                          &config.dashboard_port) != 0) return -1;
    } else if (strcmp(name, "dashboard-public-route") == 0) {
        if (!valid_dashboard_public_route(value)) return -1;
        strcpy(config.dashboard_public_route, value);
    } else if (strcmp(name, "dashboard-token-file") == 0) {
        if (copy_path(config.dashboard_token_path, sizeof(config.dashboard_token_path),
                      value, context) != 0) return -1;
    } else if (strcmp(name, "stats-file") == 0) {
        char path[sizeof(config.stats_path)];
        if (state->stats_file == context->source ||
            state->no_stats_file == context->source || !value[0] ||
            copy_path(path, sizeof(path), value, context) != 0 ||
            strlen(path) + 4 >= sizeof(config.stats_path)) return -1;
        strcpy(config.stats_path, path);
        config.stats_persistence_disabled = 0;
        state->stats_file = (unsigned char)context->source;
    } else if (strcmp(name, "no-stats-file") == 0) {
        int disabled;
        if (state->no_stats_file == context->source ||
            state->stats_file == context->source || boolean_value(value, &disabled) != 0)
            return -1;
        config.stats_persistence_disabled = disabled;
        if (disabled) config.stats_path[0] = 0;
        state->no_stats_file = (unsigned char)context->source;
    } else if (strcmp(name, "log-unknown-languages") == 0) {
        if (state->unknown_languages == context->source || !value[0] ||
            copy_path(config.unknown_languages_path,
                      sizeof(config.unknown_languages_path), value, context) != 0) return -1;
        state->unknown_languages = (unsigned char)context->source;
    } else if (strcmp(name, "allow-prefix") == 0) {
        if (config.allow_count == MAX_ALLOW || !valid_allow_prefix(value)) return -1;
        strcpy(config.allow[config.allow_count++], value);
    } else if (strncmp(name, "dots-", 5) == 0) {
        char path[512];
        if (ankah_dots_path_option(name + 5)) {
            if (copy_path(path, sizeof(path), value, context) != 0) return -1;
            value = path;
        }
        if (ankah_dots_option(name + 5, value) != 0) return -1;
    } else return -1;
    return 0;
}

static int health_argument(const char *argument, const char **name, const char **value) {
    static const char *const options[3] = {
        "--ankah-healthz", "--ankah-livez", "--ankah-readyz"
    };
    static const char *const names[3] = {
        "ankah-healthz", "ankah-livez", "ankah-readyz"
    };
    static const char *const defaults[3] = {"/healthz", "/livez", "/readyz"};
    unsigned int i;
    for (i = 0; i < 3; ++i) {
        size_t option_size = strlen(options[i]);
        if (strcmp(argument, options[i]) == 0) {
            *name = names[i];
            *value = defaults[i];
            return 1;
        }
        if (strncmp(argument, options[i], option_size) == 0 &&
            argument[option_size] == '=') {
            *name = names[i];
            *value = argument + option_size + 1;
            return 1;
        }
    }
    return 0;
}

static int find_config_file(int argc, char **argv, char *path, size_t capacity) {
    int i, seen = 0;
    for (i = 1; i < argc; ++i) {
        const char *name, *value;
        if (strcmp(argv[i], "--") == 0) break;
        if (strcmp(argv[i], "--config") == 0) {
            if (seen || i + 1 >= argc || !argv[i + 1][0] ||
                canonical_path(argv[i + 1], NULL, path, capacity) != 0) return -1;
            seen = 1;
            ++i;
        } else if (strcmp(argv[i], "--no-stats-file") == 0 ||
                   health_argument(argv[i], &name, &value)) {
            continue;
        } else if (i + 1 < argc) ++i;
    }
    return seen;
}

static int load_config_file(const char *path, option_state *state) {
    unsigned char *input;
    size_t size, at = 0;
    unsigned int line = 0;
    char directory[CONFIG_PATH_MAX];
    option_context context;
    if (path_directory(path, directory, sizeof(directory)) != 0 ||
        ankah_file_read(path, CONFIG_FILE_MAX, 0, &input, &size, NULL) != 0) {
        fprintf(stderr, "Ankah could not read configuration: %s\n", path);
        return -1;
    }
    if (memchr(input, 0, size)) {
        fprintf(stderr, "Ankah invalid configuration: %s\n", path);
        free(input);
        return -1;
    }
    context.source = OPTION_SOURCE_CONFIG;
    context.label = path;
    context.base_directory = directory;
    while (at < size) {
        char *start = (char *)input + at, *end, *equals, *key, *value;
        size_t length = 0;
        ++line;
        while (at + length < size && input[at + length] != '\n') ++length;
        if (length > CONFIG_LINE_MAX) goto invalid;
        at += length;
        if (at < size) input[at++] = 0;
        else input[at] = 0;
        end = start + length;
        while (start < end && ascii_space(*start)) ++start;
        while (end > start && ascii_space(end[-1])) --end;
        *end = 0;
        if (!*start || *start == '#') continue;
        equals = strchr(start, '=');
        if (!equals) goto invalid;
        key = start;
        end = equals;
        while (end > key && ascii_space(end[-1])) --end;
        *end = 0;
        value = equals + 1;
        while (*value && ascii_space(*value)) ++value;
        end = value + strlen(value);
        while (end > value && ascii_space(end[-1])) --end;
        *end = 0;
        if (!*key) goto invalid;
        context.line = line;
        if (apply_option(key, value, &context, state) != 0) goto invalid;
    }
    free(input);
    return 0;

invalid:
    fprintf(stderr, "Ankah invalid configuration at %s:%u\n", path, line);
    free(input);
    return -1;
}

static int apply_environment(option_state *state) {
    static const struct { const char *variable; const char *option; } options[] = {
        {"ANKAH_LISTEN", "listen"},
        {"ANKAH_UPSTREAM", "upstream"},
        {"ANKAH_PUBLIC_ORIGIN", "public-origin"},
        {"ANKAH_SECRET_FILE", "secret-file"},
        {"ANKAH_ASSETS_DIR", "assets-dir"},
        {"ANKAH_STATIC_BUNDLE", "static-bundle"},
        {"ANKAH_STATIC_CACHE_MB", "static-cache-mb"},
        {"ANKAH_MAX_UPLOAD_MB", "max-upload-mb"},
        {"ANKAH_STATIC_THROTTLE_PREFIX", "static-throttle-prefix"},
        {"ANKAH_STATIC_THROTTLE_GLOBAL_CONNECTIONS", "static-throttle-global-connections"},
        {"ANKAH_STATIC_THROTTLE_CLIENT_CONNECTIONS", "static-throttle-client-connections"},
        {"ANKAH_STATIC_THROTTLE_GLOBAL_MBPS", "static-throttle-global-mbps"},
        {"ANKAH_STATIC_THROTTLE_CLIENT_MBPS", "static-throttle-client-mbps"},
        {"ANKAH_HEALTHZ", "ankah-healthz"},
        {"ANKAH_LIVEZ", "ankah-livez"},
        {"ANKAH_READYZ", "ankah-readyz"},
        {"ANKAH_TLS_CERT", "tls-cert"},
        {"ANKAH_TLS_KEY", "tls-key"},
        {"ANKAH_HTTP3", "http3"},
        {"ANKAH_TRUSTED_PROXY", "trusted-proxy"},
        {"ANKAH_PROXY_ABUSE_PROFILE", "proxy-abuse-profile"},
        {"ANKAH_DASHBOARD_LISTEN", "dashboard-listen"},
        {"ANKAH_DASHBOARD_PUBLIC_ROUTE", "dashboard-public-route"},
        {"ANKAH_DASHBOARD_TOKEN_FILE", "dashboard-token-file"},
        {"ANKAH_STATS_FILE", "stats-file"},
        {"ANKAH_NO_STATS_FILE", "no-stats-file"},
        {"ANKAH_LOG_UNKNOWN_LANGUAGES", "log-unknown-languages"},
        {"ANKAH_ALLOW_PREFIX", "allow-prefix"},
        {"ANKAH_DOTS_SERVER", "dots-server"},
        {"ANKAH_DOTS_SERVER_NAME", "dots-server-name"},
        {"ANKAH_DOTS_PATH", "dots-path"},
        {"ANKAH_DOTS_CA_FILE", "dots-ca-file"},
        {"ANKAH_DOTS_CERT_FILE", "dots-cert-file"},
        {"ANKAH_DOTS_KEY_FILE", "dots-key-file"},
        {"ANKAH_DOTS_CUID", "dots-cuid"},
        {"ANKAH_DOTS_PROTECTED_NETWORK", "dots-protected-network"},
        {"ANKAH_DOTS_PROTECTED_PORT", "dots-protected-port"},
        {"ANKAH_DOTS_THRESHOLD", "dots-threshold"},
        {"ANKAH_DOTS_WINDOW_SECONDS", "dots-window-seconds"},
        {"ANKAH_DOTS_BLOCK_SECONDS", "dots-block-seconds"}
    };
    option_context context;
    size_t i;
    context.source = OPTION_SOURCE_ENVIRONMENT;
    context.line = 0;
    context.base_directory = NULL;
    for (i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
        const char *value = getenv(options[i].variable);
        if (!value) continue;
        context.label = options[i].variable;
        if (apply_option(options[i].option, value, &context, state) != 0) {
            fprintf(stderr, "Ankah invalid environment variable: %s\n",
                    options[i].variable);
            return -1;
        }
    }
    return 0;
}

static int finish_configuration(void) {
    {
        unsigned int left, right;
        for (left = 0; left < 3; ++left)
            for (right = left + 1; right < 3; ++right)
                if (config.health_paths[left][0] && config.health_paths[right][0] &&
                    strcmp(config.health_paths[left], config.health_paths[right]) == 0)
                    return -1;
    }
    if (!!config.throttle_prefix_count != !!config.throttle_limit_seen ||
        (config.throttle_prefix_count && !config.static_dir[0])) return -1;
    if (config.throttle_prefix_count && !config.throttle_global_connections)
        config.throttle_global_connections = MAX_THROTTLE_CONNECTIONS;
    if (config.throttle_prefix_count && !config.throttle_client_connections)
        config.throttle_client_connections = MAX_THROTTLE_CONNECTIONS;
    if (ankah_dots_finish(config.trusted_proxy_count) != 0) return -1;
    if (!prefix(config.public_origin, "https://") &&
        !prefix(config.public_origin, "http://")) return -1;
    config.public_https = prefix(config.public_origin, "https://");
    if (!!config.tls_certificate[0] != !!config.tls_key[0] ||
        (config.tls_certificate[0] && !config.public_https) ||
        !!(config.dashboard_ip[0] || config.dashboard_public_route[0]) !=
            !!config.dashboard_token_path[0] ||
        (config.stats_path[0] && config.stats_persistence_disabled)) return -1;
    config.dashboard = config.dashboard_ip[0] != 0 || config.dashboard_public_route[0] != 0;
    if (!config.dashboard && (config.stats_path[0] || config.stats_persistence_disabled))
        return -1;
    if (config.dashboard && !config.stats_path[0] && !config.stats_persistence_disabled)
        strcpy(config.stats_path, "ankah.stats");
    {
        const char *host = strstr(config.public_origin, "://") + 3;
        if (!*host || strspn(host, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                  "0123456789.-:[]") != strlen(host)) return -1;
        strcpy(config.public_host, host);
        if (config.public_https) {
            const char *port = NULL;
            if (*host == '[') {
                const char *end = strchr(host, ']');
                if (!end) return -1;
                if (end[1] == ':') port = end + 2;
                else if (end[1]) return -1;
            } else {
                const char *colon = strrchr(host, ':');
                if (colon) port = colon + 1;
            }
            config.public_h3_port = 443;
            if (port) {
                uint64_t parsed;
                if (decimal_u64(port, &parsed) != 0 || !parsed || parsed > 65535)
                    return -1;
                config.public_h3_port = (int)parsed;
            }
        }
    }
    if (config.dashboard_public_route[0]) {
        unsigned int i;
        size_t bare_length = strlen(config.dashboard_public_route) - 1;
        for (i = 0; i < 3; ++i)
            if (config.health_paths[i][0] &&
                (prefix(config.health_paths[i], config.dashboard_public_route) ||
                 (strlen(config.health_paths[i]) == bare_length &&
                  memcmp(config.health_paths[i], config.dashboard_public_route,
                         bare_length) == 0))) return -1;
    }
    if (config.secret_path[0] == 0 || load_hex_file(config.secret_path, config.secret) != 0 ||
        (config.dashboard &&
         (load_hex_file(config.dashboard_token_path, config.dashboard_token) != 0 ||
          memcmp(config.dashboard_token, config.secret, ANKAH_SECRET_SIZE) == 0 ||
          load_dashboard_assets() != 0)) ||
        load_assets() != 0 ||
        (config.static_dir[0] &&
         ankah_static_load(&config.static_bundle, config.static_dir) != 0)) return -1;
    if (config.dashboard_public_route[0] && config.static_bundle.prefix &&
        (prefix(config.dashboard_public_route, config.static_bundle.prefix) ||
         prefix(config.static_bundle.prefix, config.dashboard_public_route))) return -1;
    if (config.throttle_prefix_count) {
        unsigned int j;
        for (j = 0; j < config.throttle_prefix_count; ++j)
            if (strncmp(config.throttle_prefixes[j], config.static_bundle.prefix,
                        strlen(config.static_bundle.prefix)) != 0) return -1;
    }
    return 0;
}

static int parse_options(int argc, char **argv, int *child_index) {
    char config_path[CONFIG_PATH_MAX];
    option_state state;
    option_context context;
    int config_file, i;
    memset(&state, 0, sizeof(state));
    strcpy(config.listen_ip, "0.0.0.0");
    config.listen_port = 8000;
    config.http3_enabled = 1;
    strcpy(config.upstream_ip, "127.0.0.1");
    config.upstream_port = 8001;
    strcpy(config.assets_dir, ".");
    config.static_cache_limit = 64U * 1024U * 1024U;
    config.max_upload = (size_t)DEFAULT_MAX_UPLOAD_MB * 1024U * 1024U;
    *child_index = argc;
    config_file = find_config_file(argc, argv, config_path, sizeof(config_path));
    if (config_file < 0 || (config_file && load_config_file(config_path, &state) != 0) ||
        apply_environment(&state) != 0) return -1;
    context.source = OPTION_SOURCE_COMMAND_LINE;
    context.label = NULL;
    context.line = 0;
    context.base_directory = NULL;
    for (i = 1; i < argc; ++i) {
        const char *name, *value;
        if (strcmp(argv[i], "--") == 0) {
            *child_index = i + 1;
            break;
        }
        if (strcmp(argv[i], "--config") == 0) {
            ++i;
            continue;
        }
        if (strcmp(argv[i], "--no-stats-file") == 0) {
            if (apply_option("no-stats-file", "true", &context, &state) != 0) return -1;
            continue;
        }
        if (health_argument(argv[i], &name, &value)) {
            if (apply_option(name, value, &context, &state) != 0) return -1;
            continue;
        }
        if (strncmp(argv[i], "--proxy-abuse-profile=", 22) == 0) {
            if (apply_option("proxy-abuse-profile", argv[i] + 22,
                             &context, &state) != 0) return -1;
            continue;
        }
        if (strncmp(argv[i], "--dashboard-public-route=", 25) == 0) {
            if (apply_option("dashboard-public-route", argv[i] + 25,
                             &context, &state) != 0) return -1;
            continue;
        }
        if (i + 1 >= argc || strncmp(argv[i], "--", 2) != 0) return -1;
        name = argv[i] + 2;
        value = argv[++i];
        if (apply_option(name, value, &context, &state) != 0) return -1;
    }
    return finish_configuration();
}

static void on_handle_closed(uv_handle_t *handle) {
    connection *c = (connection *)handle->data;
    if (--c->handles == 0) {
        if (c->dashboard) --config.dashboard_connections;
        else {
            --config.connections;
            if (c->admission_state == 0) --config.pending_connections;
            else if (c->admission_state == 1) --config.anonymous_connections;
        }
        free(c);
    }
}

static void close_connection(connection *c) {
    if (c->closed) return;
    c->closed = 1;
    if (c->bing_pending) ankah_bingbot_verify_cancel(c);
    release_crawler_slot(c);
    if (!c->crawler) release_external_crawler_slot(c);
    if (c->drain_tracked) {
        c->drain_tracked = 0;
        if (config.active_requests) --config.active_requests;
    }
    throttle_release(c);
    registry_unlink(c);
    all_unlink(c);
    body_release(c->body_pin);
    c->body_pin = NULL;
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
    maybe_finish_drain();
}

static void on_client_shutdown(uv_shutdown_t *request, int status) {
    connection *c = (connection *)request->data;
    if (c->closed) return;
    if (status < 0) {
        close_connection(c);
        return;
    }
    c->client_shutdown_done = 1;
    if (c->client_read_eof) close_connection(c);
}

/* Keep reading the abandoned request until the peer closes its write side.
 * Closing a socket with unread input can reset and discard its response. */
static void finish_upstream_response(connection *c) {
    int result;
    if (c->closed || c->response_finishing) return;
    c->response_finishing = 1;
    c->reply_deadline_ns = 0;
    c->request_deadline_ns = uv_hrtime() + UINT64_C(30000000000);
    uv_read_stop((uv_stream_t *)&c->upstream);
    if (!uv_is_closing((uv_handle_t *)&c->upstream))
        uv_close((uv_handle_t *)&c->upstream, on_handle_closed);
    refresh_timeout(c);
    if (c->closed) return;
    result = uv_read_start((uv_stream_t *)&c->client, allocate_read, on_client_read);
    if (result < 0 && result != UV_EALREADY) { close_connection(c); return; }
    c->client_shutdown.data = c;
    if (uv_shutdown(&c->client_shutdown, (uv_stream_t *)&c->client,
                    on_client_shutdown) != 0) close_connection(c);
}

static int request_body_complete(const connection *c);
static void abuse_event(connection *c, ankah_abuse_event event, const char *path) {
    if (!c->trusted_direct_peer) return;
    if (ankah_abuse_record(config.abuse_policy, c->peer_ip, event, path, uv_hrtime())) {
        c->abuse_action = 1;
    }
}
static void on_timeout(uv_timer_t *timer) {
    connection *c = (connection *)timer->data;
    if (c->headers_handled && c->request.method[0] && !request_body_complete(c) &&
        !c->response_started && !c->upstream_final_started && !c->status_seen &&
        !c->pending_client && c->trusted_direct_peer) {
        uv_timer_stop(timer);
        uv_read_stop((uv_stream_t *)&c->client);
        if (c->upstream_initialized) uv_read_stop((uv_stream_t *)&c->upstream);
        abuse_event(c, ANKAH_ABUSE_BODY_STALL, NULL);
        respond(c, 408, "Request Timeout", "text/plain", "Request body timed out\n", NULL);
        return;
    }
    close_connection(c);
}

static int request_body_complete(const connection *c) {
    return c->request.chunked ? c->chunked_body.complete :
           c->body_received == c->request.content_length;
}

static void refresh_timeout(connection *c) {
    uint64_t timeout = ankah_core_timeout_ms(uv_hrtime(), c->request_deadline_ns,
                                              c->reply_deadline_ns, c->websocket);
    if (!timeout) { close_connection(c); return; }
    uv_timer_start(&c->timer, on_timeout, timeout, 0);
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
    int to_client = request->handle == (uv_stream_t *)&c->client;
    if (status >= 0) {
        if (to_client) {
            tally(c, ANKAH_STAT_client_bytes_out, write->buffer.len);
            c->bytes_out += write->buffer.len;
            if (c->throttled) refresh_timeout(c);
        } else tally(c, ANKAH_STAT_upstream_bytes_out, write->buffer.len);
    }
    free(write->buffer.base);
    free(write);
    --c->pending;
    if (to_client) --c->pending_client;
    else --c->pending_upstream;
    if (c->closed) return;
    if (c->response_finishing) {
        if (status < 0 && to_client) close_connection(c);
        return;
    }
    if (status < 0 && !to_client) {
        /* A peer can close its request side after sending an early response.
         * Let the upstream read callback deliver that response or report EOF. */
        c->forwarding = 0;
        c->request_deadline_ns = 0;
        uv_read_stop((uv_stream_t *)&c->client);
        refresh_timeout(c);
        return;
    }
    if (status < 0 || finish) {
        close_connection(c);
        return;
    }
    if ((c->asset_index >= 0 || c->segmented) && c->pending == 0 &&
        !(c->throttled && config.lifecycle == LIFECYCLE_RUNNING &&
          (config.throttle_global_bytes_per_second ||
                           config.throttle_client_bytes_per_second))) {
        send_asset_chunk(c);
        return;
    }
    if (c->replaying && c->pending == 0) {
        send_replay_chunk(c);
        return;
    }
    if (!c->closed && source &&
        (to_client ? c->pending_client : c->pending_upstream) < MAX_PENDING_WRITES) {
        uv_read_start(source, allocate_read,
                      source == (uv_stream_t *)&c->client ? on_client_read : on_upstream_read);
    }
}

static int queue_bytes(connection *c, uv_stream_t *destination,
                       uv_stream_t *source, const char *data, size_t length, int finish) {
    queued_write *write = (queued_write *)calloc(1, sizeof(*write));
    uv_buf_t buffers[1];
    unsigned int *destination_pending = destination == (uv_stream_t *)&c->client ?
                                        &c->pending_client : &c->pending_upstream;
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
    ++*destination_pending;
    buffers[0] = write->buffer;
    result = uv_write(&write->request, destination, buffers, 1, on_write);
    if (result < 0) {
        --c->pending;
        --*destination_pending;
        free(write->buffer.base);
        free(write);
        return -1;
    }
    if (source && *destination_pending >= MAX_PENDING_WRITES) uv_read_stop(source);
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

static size_t send_asset_chunk_limit(connection *c, size_t limit) {
    const unsigned char *data;
    size_t size;
    size_t remaining, amount;
    if (c->closed || !limit) return 0;
    if (c->segmented) {
        while (c->segment_index < c->segment_count &&
               c->segment_offset == c->segments[c->segment_index].size) {
            ++c->segment_index;
            c->segment_offset = 0;
        }
        if (c->segment_index == c->segment_count) {
            close_connection(c);
            return 0;
        }
        data = c->segments[c->segment_index].data;
        size = c->segments[c->segment_index].size;
        remaining = size - c->segment_offset;
        amount = remaining < THROTTLE_CHUNK ? remaining : THROTTLE_CHUNK;
        if (amount > limit) amount = limit;
        c->segment_offset += amount;
        if (queue_bytes(c, (uv_stream_t *)&c->client, NULL,
                        (const char *)data + c->segment_offset - amount, amount,
                        c->segment_index + 1 == c->segment_count &&
                        c->segment_offset == size) != 0) {
            close_connection(c);
            return 0;
        }
        return amount;
    } else if (c->asset_index >= 0) {
        data = config.assets[c->asset_index].data;
        size = config.assets[c->asset_index].size;
    } else return 0;
    remaining = size - c->asset_offset;
    if (!remaining) { close_connection(c); return 0; }
    amount = remaining < THROTTLE_CHUNK ? remaining : THROTTLE_CHUNK;
    if (amount > limit) amount = limit;
    c->asset_offset += amount;
    if (queue_bytes(c, (uv_stream_t *)&c->client, NULL,
                    (const char *)data + c->asset_offset - amount,
                    amount, c->asset_offset == size) != 0) {
        close_connection(c);
        return 0;
    }
    return amount;
}

static void send_asset_chunk(connection *c) {
    (void)send_asset_chunk_limit(c, THROTTLE_CHUNK);
}

static double throttle_bucket_capacity(uint64_t rate) {
    double capacity = (double)rate * (double)THROTTLE_BURST_NS / 1000000000.0;
    return capacity < 1.0 ? 1.0 : capacity;
}

static void throttle_refill(double *tokens, uint64_t *last_ns,
                            uint64_t rate, uint64_t now) {
    double capacity;
    if (!rate) return;
    capacity = throttle_bucket_capacity(rate);
    if (!*last_ns) *tokens = capacity;
    else {
        *tokens += (double)(now - *last_ns) * (double)rate / 1000000000.0;
        if (*tokens > capacity) *tokens = capacity;
    }
    *last_ns = now;
}

static connection *throttle_ready_transfer(throttle_client *client) {
    connection *start, *c;
    if (!client->transfers) return NULL;
    start = client->cursor ? client->cursor : client->transfers;
    c = start;
    do {
        connection *next = c->throttle_next ? c->throttle_next : client->transfers;
        client->cursor = next;
        if (!c->closed && c->pending == 0) return c;
        c = next;
    } while (c != start);
    return NULL;
}

static void on_throttle_tick(uv_timer_t *timer) {
    uint64_t now = uv_hrtime();
    unsigned int scanned, start = config.throttle_client_cursor;
    int advanced = 0;
    (void)timer;
    if (!config.throttle_active) return;
    throttle_refill(&config.throttle_global_tokens,
                    &config.throttle_global_last_ns,
                    config.throttle_global_bytes_per_second, now);
    for (scanned = 0; scanned < MAX_THROTTLE_CLIENTS; ++scanned) {
        unsigned int index = (start + scanned) % MAX_THROTTLE_CLIENTS;
        throttle_client *client = &config.throttle_clients[index];
        connection *c;
        double allowance = THROTTLE_CHUNK;
        size_t sent;
        if (!client->active) continue;
        throttle_refill(&client->tokens, &client->last_ns,
                        config.throttle_client_bytes_per_second, now);
        if (config.throttle_global_bytes_per_second &&
            allowance > config.throttle_global_tokens)
            allowance = config.throttle_global_tokens;
        if (config.throttle_client_bytes_per_second && allowance > client->tokens)
            allowance = client->tokens;
        if (allowance < 1.0) continue;
        c = throttle_ready_transfer(client);
        if (!c) continue;
        sent = send_asset_chunk_limit(c, (size_t)allowance);
        if (!sent) continue;
        if (config.throttle_global_bytes_per_second)
            config.throttle_global_tokens -= (double)sent;
        if (config.throttle_client_bytes_per_second)
            client->tokens -= (double)sent;
        config.throttle_client_cursor = (index + 1) % MAX_THROTTLE_CLIENTS;
        advanced = 1;
        break;
    }
    if (!advanced) config.throttle_client_cursor = (start + 1) % MAX_THROTTLE_CLIENTS;
}

static void throttle_release(connection *c) {
    throttle_client *client = c->throttle_client;
    if (!c->throttled || !client) return;
    if (c->throttle_previous) c->throttle_previous->throttle_next = c->throttle_next;
    else client->transfers = c->throttle_next;
    if (c->throttle_next) c->throttle_next->throttle_previous = c->throttle_previous;
    if (client->cursor == c)
        client->cursor = c->throttle_next ? c->throttle_next : client->transfers;
    if (client->active) --client->active;
    if (config.throttle_active) --config.throttle_active;
    c->throttle_client = NULL;
    c->throttle_previous = c->throttle_next = NULL;
    c->throttled = 0;
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
    tally_status(c, cached ? 304 : 200);
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
            ankah_stats_add(ANKAH_STAT_cache_hits, 1);
            return item;
        }
    }
    ankah_stats_add(ANKAH_STAT_cache_misses, 1);
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
        if (!ankah_header_is(&request->headers[i], ANKAH_HEADER_ACCEPT_ENCODING)) continue;
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
                if (!same_ascii_part(p, 2, "q=")) q = 0;
                else {
                    p += 2;
                    q = parse_quality(p, &p);
                    if (q < 0) q = 0;
                }
            }
            while (*p && *p != ',') ++p;
            end = token_end;
            if ((size_t)(end - token) == strlen(name) &&
                same_ascii_part(token, (size_t)(end - token), name)) explicit_q = q;
            if (end - token == 1 && *token == '*') wildcard_q = q;
        }
    }
    if (!found) return identity ? 1000 : 0;
    if (explicit_q >= 0) return explicit_q;
    if (identity) return wildcard_q == 0 ? 0 : 1000;
    return wildcard_q >= 0 ? wildcard_q : 0;
}

static int media_quality(const char *value, size_t length) {
    size_t i = 0, digits = 0;
    int whole, fraction = 0;
    if (!length || (value[0] != '0' && value[0] != '1')) return -1;
    whole = value[i++] - '0';
    if (i < length && value[i] == '.') {
        ++i;
        while (i < length && value[i] >= '0' && value[i] <= '9') {
            if (++digits > 3) return -1;
            fraction = fraction * 10 + value[i++] - '0';
        }
    }
    if (i != length || (whole && fraction)) return -1;
    while (digits++ < 3) fraction *= 10;
    return whole ? 1000 : fraction;
}

static int accepts_html(const ankah_request *request) {
    unsigned int i;
    int best = -1;
    for (i = 0; i < request->count; ++i) {
        const char *p;
        if (!same_ascii(request->headers[i].name, "Accept")) continue;
        p = request->headers[i].value;
        while (*p) {
            const char *item, *item_end, *media_end, *parameter;
            int quality = 1000;
            while (*p == ',' || *p == ' ' || *p == '\t') ++p;
            item = p;
            while (*p && *p != ',') ++p;
            item_end = p;
            while (item_end > item &&
                   (item_end[-1] == ' ' || item_end[-1] == '\t')) --item_end;
            media_end = item;
            while (media_end < item_end && *media_end != ';') ++media_end;
            while (media_end > item &&
                   (media_end[-1] == ' ' || media_end[-1] == '\t')) --media_end;
            if (!same_ascii_part(item, (size_t)(media_end - item), "text/html"))
                continue;
            parameter = media_end;
            while (parameter < item_end) {
                const char *name, *name_end, *value, *value_end;
                while (parameter < item_end &&
                       (*parameter == ';' || *parameter == ' ' || *parameter == '\t'))
                    ++parameter;
                name = parameter;
                while (parameter < item_end && *parameter != '=' && *parameter != ';')
                    ++parameter;
                name_end = parameter;
                while (name_end > name &&
                       (name_end[-1] == ' ' || name_end[-1] == '\t')) --name_end;
                if (parameter == item_end || *parameter != '=') {
                    while (parameter < item_end && *parameter != ';') ++parameter;
                    continue;
                }
                ++parameter;
                while (parameter < item_end && (*parameter == ' ' || *parameter == '\t'))
                    ++parameter;
                value = parameter;
                while (parameter < item_end && *parameter != ';') ++parameter;
                value_end = parameter;
                while (value_end > value &&
                       (value_end[-1] == ' ' || value_end[-1] == '\t')) --value_end;
                if (same_ascii_part(name, (size_t)(name_end - name), "q")) {
                    quality = media_quality(value, (size_t)(value_end - value));
                    if (quality < 0) quality = 0;
                }
            }
            if (quality > best) best = quality;
        }
    }
    return best > 0;
}

static int optional_header_is(const ankah_request *request, const char *name,
                              const char *expected) {
    unsigned int i;
    for (i = 0; i < request->count; ++i)
        if (same_ascii(request->headers[i].name, name) &&
            !same_ascii(request->headers[i].value, expected)) return 0;
    return 1;
}

static int spa_navigation(const connection *c, const char *path) {
    const char *segment, *p;
    size_t length;
    if (!config.static_bundle.fallback_url ||
        strncmp(path, config.static_bundle.prefix,
                strlen(config.static_bundle.prefix)) != 0 ||
        (strcmp(c->request.method, "GET") != 0 &&
         strcmp(c->request.method, "HEAD") != 0) ||
        c->request.has_body || c->request.websocket ||
        ankah_header_value(&c->request, "Range") || !accepts_html(&c->request) ||
        !optional_header_is(&c->request, "Sec-Fetch-Mode", "navigate") ||
        !optional_header_is(&c->request, "Sec-Fetch-Dest", "document")) return 0;
    length = strlen(path);
    while (length && path[length - 1] == '/') --length;
    segment = path;
    for (p = path; (size_t)(p - path) < length; ++p)
        if (*p == '/') segment = p + 1;
    for (p = segment; (size_t)(p - path) < length; ++p)
        if (*p == '.' || (*p == '%' && (size_t)(p - path) + 2 < length &&
            p[1] == '2' && (p[2] == 'e' || p[2] == 'E'))) return 0;
    return 1;
}

static int etag_matches(const ankah_request *request, const char *etag) {
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        const char *p;
        if (!ankah_header_is(&request->headers[i], ANKAH_HEADER_IF_NONE_MATCH)) continue;
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

static const char *pass_cookie_value(const ankah_request *request,
                                     char out[ANKAH_PASS_TEXT_MAX]) {
    const char *cookie = ankah_header_value(request, "Cookie");
    const char *item;
    size_t length;
    if (!cookie) return NULL;
    item = strstr(cookie, "ankah_pass=");
    if (!item || (item != cookie && item[-1] != ' ' && item[-1] != ';')) return NULL;
    item += strlen("ankah_pass=");
    length = strcspn(item, "; \r\n");
    if (!length || length >= ANKAH_PASS_TEXT_MAX) return NULL;
    memcpy(out, item, length);
    out[length] = 0;
    return out;
}

static int request_throttle_identity(const ankah_request *request,
                                     char out[ANKAH_CLIENT_ID_TEXT_SIZE]) {
    ankah_session *session = request_session(request);
    char pass[ANKAH_PASS_TEXT_MAX];
    uint64_t now = (uint64_t)time(NULL);
    if (ankah_session_solved(session, now)) {
        memcpy(out, session->id, ANKAH_CLIENT_ID_TEXT_SIZE);
        return 0;
    }
    if (!pass_cookie_value(request, pass)) return -1;
    return ankah_check_pass_identity(config.secret, config.public_host, now, pass, out);
}

static int throttle_path_matches(const char *path) {
    unsigned int i;
    for (i = 0; i < config.throttle_prefix_count; ++i)
        if (strncmp(path, config.throttle_prefixes[i],
                    strlen(config.throttle_prefixes[i])) == 0) return 1;
    return 0;
}

static void throttle_prune_queue(uint64_t now) {
    unsigned int i;
    for (i = 0; i < MAX_THROTTLE_QUEUE; ++i) {
        throttle_queue_entry *item = &config.throttle_queue[i];
        if (!item->active || now - item->seen_ns <= THROTTLE_QUEUE_TTL_NS) continue;
        if (item->client && item->client->queued) --item->client->queued;
        memset(item, 0, sizeof(*item));
        if (config.throttle_queue_count) --config.throttle_queue_count;
    }
}

static throttle_client *throttle_client_for(const char *id) {
    throttle_client *oldest = NULL;
    unsigned int i;
    for (i = 0; i < MAX_THROTTLE_CLIENTS; ++i) {
        throttle_client *client = &config.throttle_clients[i];
        if (client->id[0] && strcmp(client->id, id) == 0) return client;
        if (!client->active && !client->queued &&
            (!oldest || !client->id[0] || client->last_ns < oldest->last_ns)) {
            oldest = client;
            if (!client->id[0]) break;
        }
    }
    if (!oldest) return NULL;
    memset(oldest, 0, sizeof(*oldest));
    memcpy(oldest->id, id, ANKAH_CLIENT_ID_TEXT_SIZE);
    return oldest;
}

static throttle_queue_entry *throttle_queue_find(throttle_client *client,
                                                  const ankah_static_entry *entry) {
    unsigned int i;
    for (i = 0; i < MAX_THROTTLE_QUEUE; ++i)
        if (config.throttle_queue[i].active &&
            config.throttle_queue[i].client == client &&
            config.throttle_queue[i].entry == entry) return &config.throttle_queue[i];
    return NULL;
}

static throttle_queue_entry *throttle_oldest_eligible(void) {
    throttle_queue_entry *oldest = NULL;
    unsigned int i;
    for (i = 0; i < MAX_THROTTLE_QUEUE; ++i) {
        throttle_queue_entry *item = &config.throttle_queue[i];
        if (!item->active || !item->client ||
            item->client->active >= config.throttle_client_connections) continue;
        if (!oldest || item->sequence < oldest->sequence) oldest = item;
    }
    return oldest;
}

static void throttle_queue_remove(throttle_queue_entry *item) {
    if (!item || !item->active) return;
    if (item->client && item->client->queued) --item->client->queued;
    memset(item, 0, sizeof(*item));
    if (config.throttle_queue_count) --config.throttle_queue_count;
}

static void throttle_link(connection *c, throttle_client *client) {
    c->throttled = 1;
    c->throttle_client = client;
    c->throttle_previous = NULL;
    c->throttle_next = client->transfers;
    if (c->throttle_next) c->throttle_next->throttle_previous = c;
    client->transfers = c;
    if (!client->cursor) client->cursor = c;
    ++client->active;
    ++config.throttle_active;
    tally_max(c, ANKAH_STAT_peak_throttle_connections, config.throttle_active);
}

/* Returns 1 when admitted, 0 when queued, and -1 when the bounded queue is full. */
static int throttle_admit(connection *c, const ankah_static_entry *entry,
                          const char *identity, uint64_t *wait_ms,
                          unsigned int *position, unsigned int *depth) {
    throttle_client *client;
    throttle_queue_entry *queued, *oldest;
    uint64_t now = uv_hrtime();
    unsigned int i;
    throttle_prune_queue(now);
    client = throttle_client_for(identity);
    if (!client) return -1;
    queued = throttle_queue_find(client, entry);
    if (queued) queued->seen_ns = now;
    oldest = throttle_oldest_eligible();
    if (config.throttle_active < config.throttle_global_connections &&
        client->active < config.throttle_client_connections &&
        ((!queued && !oldest) || queued == oldest)) {
        *wait_ms = queued ? (now - queued->queued_ns + 999999) / 1000000 : 0;
        if (queued) throttle_queue_remove(queued);
        throttle_link(c, client);
        return 1;
    }
    if (!queued) {
        if (client->queued >= MAX_THROTTLE_QUEUE_PER_CLIENT ||
            config.throttle_queue_count >= MAX_THROTTLE_QUEUE) return -1;
        for (i = 0; i < MAX_THROTTLE_QUEUE; ++i)
            if (!config.throttle_queue[i].active) break;
        if (i == MAX_THROTTLE_QUEUE) return -1;
        queued = &config.throttle_queue[i];
        queued->active = 1;
        queued->client = client;
        queued->entry = entry;
        queued->sequence = ++config.throttle_sequence;
        queued->queued_ns = queued->seen_ns = now;
        ++client->queued;
        ++config.throttle_queue_count;
        tally_max(c, ANKAH_STAT_peak_throttle_queue, config.throttle_queue_count);
    }
    *position = 1;
    for (i = 0; i < MAX_THROTTLE_QUEUE; ++i)
        if (config.throttle_queue[i].active &&
            config.throttle_queue[i].sequence < queued->sequence) ++*position;
    *depth = config.throttle_queue_count;
    return 0;
}

static void static_discard_body(connection *c) {
    if (c->cache_pin) {
        --c->cache_pin->pins;
        c->cache_pin = NULL;
    }
    c->segment_count = c->segment_index = 0;
    c->segment_offset = c->segment_headers_used = 0;
    c->static_entry = NULL;
    c->segmented = 0;
}

static void respond_throttle_queue(connection *c, int full,
                                   unsigned int position, unsigned int depth) {
    char body[1024], extra[384];
    ankah_language language = ankah_language_select(&c->request);
    int length;
    if (full)
        length = snprintf(body, sizeof(body),
            "<!doctype html><html lang=%s><meta charset=utf-8>"
            "<meta http-equiv=refresh content=1><title>%s</title>"
            "<body><main><h1>%s</h1><p>%s</p>"
            "<p><a href=''>%s</a></p></main></body></html>",
            ankah_language_tag(language),
            ankah_language_message(language, "Download queue full"),
            ankah_language_message(language, "Download queue full"),
            ankah_language_message(language,
                "The bounded queue is full. Retrying in one second."),
            ankah_language_message(language, "Retry now"));
    else
        length = snprintf(body, sizeof(body),
            "<!doctype html><html lang=%s><meta charset=utf-8>"
            "<meta http-equiv=refresh content=1><title>%s</title>"
            "<body><main><h1>%s</h1><p>",
            ankah_language_tag(language),
            ankah_language_message(language, "Download queued"),
            ankah_language_message(language, "Download queued"));
    if (!full && length >= 0 && (size_t)length < sizeof(body)) {
        int more = snprintf(body + length, sizeof(body) - (size_t)length,
            ankah_language_message(language, "Your position is %u of %u."),
            position, depth);
        if (more < 0 || (size_t)more >= sizeof(body) - (size_t)length) {
            close_connection(c); return;
        }
        length += more;
        more = snprintf(body + length, sizeof(body) - (size_t)length,
            "</p><p>%s</p><p><a href=''>%s</a></p></main></body></html>",
            ankah_language_message(language, "Retrying in one second."),
            ankah_language_message(language, "Retry now"));
        if (more < 0 || (size_t)more >= sizeof(body) - (size_t)length) {
            close_connection(c); return;
        }
        length += more;
    }
    if (length < 0 || (size_t)length >= sizeof(body)) { close_connection(c); return; }
    length = snprintf(extra, sizeof(extra),
        "Retry-After: 1\r\nContent-Security-Policy: default-src 'none'; "
        "style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'\r\n");
    if (length < 0 || (size_t)length >= sizeof(extra)) { close_connection(c); return; }
    tally(c, ANKAH_STAT_rate_limited, 1);
    tally(c, ANKAH_STAT_throttle_queue_responses, 1);
    respond(c, 429, "Too Many Requests", "text/html; charset=utf-8", body, extra);
}

static int serve_static_entry(connection *c, const ankah_static_entry *entry,
                              int fallback, const char *throttle_identity) {
    char response[1024], part[512], boundary[48];
    char content_type[256], range_field[128];
    const ankah_static_variant *variant;
    const unsigned char *data;
    const char *range_header, *if_range, *encoding = NULL;
    const char *cache_control, *vary;
    byte_range ranges[MAX_STATIC_RANGES];
    size_t body_size;
    int cached, head, written, code = 200, range_count = 0, selected = -1;
    int best_quality = 0, i;
    tally(c, ANKAH_STAT_static_requests, 1);
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
            char unavailable[512];
            ankah_language language = ankah_language_select(&c->request);
            const char *body = ankah_language_message(language,
                "No acceptable static representation\n");
            int amount = snprintf(unavailable, sizeof(unavailable),
                "HTTP/1.1 406 Not Acceptable\r\nContent-Type: text/plain; charset=utf-8\r\n"
                "Content-Length: %zu\r\nVary: Accept-Encoding, Accept-Language\r\n"
                "Content-Language: %s\r\nCache-Control: no-store\r\n"
                "X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
                strlen(body), ankah_language_tag(language));
            tally_status(c, 406);
            if (amount < 0 || (size_t)amount >= sizeof(unavailable) ||
                queue_bytes(c, (uv_stream_t *)&c->client, NULL, unavailable,
                            (size_t)amount, 1) != 0) close_connection(c);
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
    cache_control = fallback ? "private, no-cache" :
        entry->immutable ? "public, max-age=31536000, immutable" :
                           "public, max-age=60";
    vary = fallback ? "Accept, Sec-Fetch-Mode, Sec-Fetch-Dest, Accept-Encoding" :
                      "Accept-Encoding";
    written = snprintf(response, sizeof(response),
                       "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                       "Content-Length: %zu\r\nCache-Control: %s\r\n"
                       "ETag: %s\r\nVary: %s\r\nAccept-Ranges: bytes\r\n"
                       "X-Content-Type-Options: nosniff\r\n%s%sConnection: close\r\n\r\n",
                       cached ? 304 : code,
                       cached ? "Not Modified" : code == 206 ? "Partial Content" :
                       code == 416 ? "Range Not Satisfiable" : "OK",
                       content_type,
                       cached ? variant->size : body_size,
                       cache_control, variant->etag, vary,
                       encoding ? (selected == 1 ? "Content-Encoding: gzip\r\n" :
                                                   "Content-Encoding: br\r\n") : "",
                       range_field);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        goto failed;
    }
    if (throttle_identity && !cached && code != 416 && !head && body_size) {
        uint64_t wait_ms = 0;
        unsigned int position = 0, depth = 0;
        int admission = throttle_admit(c, entry, throttle_identity, &wait_ms,
                                       &position, &depth);
        if (admission <= 0) {
            static_discard_body(c);
            respond_throttle_queue(c, admission < 0, position, depth);
            return 1;
        }
        if (wait_ms) {
            tally(c, ANKAH_STAT_throttle_queued_requests, 1);
            tally(c, ANKAH_STAT_throttle_wait_ms_total, wait_ms);
            tally_max(c, ANKAH_STAT_throttle_wait_ms_peak, wait_ms);
        }
        tally(c, ANKAH_STAT_throttled_static_bytes, body_size);
    }
    if (throttle_identity) tally(c, ANKAH_STAT_throttled_static_requests, 1);
    tally_status(c, cached ? 304 : code);
    if (!cached && code != 416 && !head && body_size) {
        c->static_entry = entry;
        c->segmented = 1;
        tally(c, ANKAH_STAT_static_bytes, body_size);
    }
    if (queue_bytes(c, (uv_stream_t *)&c->client, NULL, response, (size_t)written,
                    !c->static_entry) != 0) close_connection(c);
    return 1;
failed:
    close_connection(c);
    return 1;
}

static int static_request_path(const connection *c, char path[ANKAH_MAX_TARGET]) {
    const char *query = strchr(c->request.target, '?');
    size_t length = query ? (size_t)(query - c->request.target) :
                            strlen(c->request.target);
    if (length >= ANKAH_MAX_TARGET) return -1;
    memcpy(path, c->request.target, length);
    path[length] = 0;
    return 0;
}

/* True when the static bundle answers this request, with a file or with a
 * 404 inside its namespace. */
static int static_route(const connection *c) {
    char path[ANKAH_MAX_TARGET];
    if (!config.static_bundle.prefix || static_request_path(c, path) != 0) return 0;
    return ankah_static_find(&config.static_bundle, path) ||
           (!spa_navigation(c, path) &&
            ankah_static_in_namespace(&config.static_bundle, path));
}

static int serve_static_if_matched(connection *c) {
    const ankah_static_entry *entry;
    char path[ANKAH_MAX_TARGET];
    if (!static_route(c) || static_request_path(c, path) != 0) return 0;
    entry = ankah_static_find(&config.static_bundle, path);
    if (entry) {
        if (throttle_path_matches(path)) {
            char identity[ANKAH_CLIENT_ID_TEXT_SIZE];
            if (request_throttle_identity(&c->request, identity) != 0) {
                handle_challenge(c);
                return 1;
            }
            return serve_static_entry(c, entry, 0, identity);
        }
        return serve_static_entry(c, entry, 0, NULL);
    }
    tally(c, ANKAH_STAT_static_requests, 1);
    respond(c, 404, "Not Found", "text/plain", "Unknown static file\n", NULL);
    return 1;
}

static int spa_route(const connection *c) {
    char path[ANKAH_MAX_TARGET];
    return static_request_path(c, path) == 0 && spa_navigation(c, path) &&
           ankah_static_fallback(&config.static_bundle) != NULL;
}

static int serve_spa_fallback(connection *c) {
    if (!spa_route(c)) return 0;
    return serve_static_entry(c, ankah_static_fallback(&config.static_bundle), 1, NULL);
}

static void respond(connection *c, int status, const char *reason,
                    const char *type, const char *body, const char *extra) {
    char response[16384];
    size_t body_size;
    char localized_headers[64];
    const char *language_headers = "";
    const char *charset = "";
    int human_text = strncmp(type, "text/plain", 10) == 0 ||
                     strncmp(type, "text/html", 9) == 0;
    int length;
    tally_status(c, status);
    c->response_started = 1;
    if (human_text) {
        ankah_language language = ankah_language_select(&c->request);
        body = ankah_language_message(language, body);
        int localized_length = snprintf(
            localized_headers, sizeof(localized_headers),
            "Content-Language: %s\r\nVary: Accept-Language\r\n",
            ankah_language_tag(language));
        if (localized_length < 0 ||
            (size_t)localized_length >= sizeof(localized_headers)) {
            close_connection(c);
            return;
        }
        language_headers = localized_headers;
        if (strcmp(type, "text/plain") == 0) charset = "; charset=utf-8";
    }
    body_size = strlen(body);
    length = snprintf(response, sizeof(response),
                          "HTTP/1.1 %d %s\r\nContent-Type: %s%s\r\n"
                          "Content-Length: %zu\r\nCache-Control: no-store\r\n"
                          "X-Content-Type-Options: nosniff\r\n"
                          "Referrer-Policy: no-referrer\r\n"
                          "%sConnection: close\r\n%s%s\r\n%s",
                          status, reason, type, charset, body_size, language_headers,
                          extra ? extra : "",
                          c->abuse_action ? "Ankah-Proxy-Action: block\r\n" : "", body);
    if (length < 0 || (size_t)length >= sizeof(response) ||
        queue_bytes(c, (uv_stream_t *)&c->client, NULL, response, (size_t)length, 1) != 0)
        close_connection(c);
}

static int health_path_matches(const char *target, const char *path) {
    size_t length;
    if (!path[0]) return 0;
    length = strcspn(target, "?");
    return strlen(path) == length && memcmp(target, path, length) == 0;
}

static int health_route_index(const connection *c) {
    unsigned int i;
    for (i = 0; i < 3; ++i)
        if (health_path_matches(c->request.target, config.health_paths[i])) return (int)i;
    return -1;
}

static int health_route(const connection *c) {
    return health_route_index(c) >= 0;
}

static int serve_health_if_matched(connection *c) {
    static const char body[] = "ok\n";
    char response[512];
    int length, head;
    if (!health_route(c)) return 0;
    head = strcmp(c->request.method, "HEAD") == 0;
    if (strcmp(c->request.method, "GET") != 0 && !head) {
        respond(c, 405, "Method Not Allowed", "text/plain; charset=utf-8",
                "Use GET or HEAD\n", "Allow: GET, HEAD\r\n");
        return 1;
    }
    tally_status(c, 200);
    length = snprintf(response, sizeof(response),
                      "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                      "Content-Length: %zu\r\nCache-Control: no-store\r\n"
                      "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
                      "Connection: close\r\n\r\n%s",
                      sizeof(body) - 1, head ? "" : body);
    if (length < 0 || (size_t)length >= sizeof(response) ||
        queue_bytes(c, (uv_stream_t *)&c->client, NULL,
                    response, (size_t)length, 1) != 0) close_connection(c);
    return 1;
}

static int admit_request(connection *c) {
    const char *admitted;
    int health;
    if (config.lifecycle == LIFECYCLE_RUNNING) {
        c->drain_tracked = 1;
        ++config.active_requests;
        return 1;
    }
    admitted = c->internal
        ? ankah_header_value(&c->request, "X-Ankah-Internal-Drain") : NULL;
    if (admitted && strcmp(admitted, "1") == 0) {
        c->drain_tracked = 1;
        ++config.active_requests;
        return 1;
    }
    health = health_route_index(c);
    if (health >= 0 && health != 2) {
        serve_health_if_matched(c);
        return 0;
    }
    respond(c, 503, "Service Unavailable", "text/plain",
            "Service shutting down\n", "Retry-After: 1\r\n");
    return 0;
}

static int cookie_valid(const ankah_request *request) {
    char pass[ANKAH_PASS_TEXT_MAX];
    if (!pass_cookie_value(request, pass)) return 0;
    return ankah_check_pass(config.secret, config.public_host,
                            (uint64_t)time(NULL), pass) == 0;
}

static int request_proved(const ankah_request *request) {
    return ankah_session_solved(request_session(request), (uint64_t)time(NULL)) ||
           cookie_valid(request);
}

static int claims_bingbot(const ankah_request *request) {
    const char *agent = ankah_header_value(request, "User-Agent");
    return agent && contains_ascii(agent, "bingbot");
}

static rate_class request_rate_class(const ankah_request *request, int proved,
                                     int crawler) {
    if (crawler && !prefix(request->target, "/ankah/")) return RATE_CRAWLER;
    return proved && !prefix(request->target, "/ankah/") ?
        RATE_PROTECTED : RATE_ANONYMOUS;
}

static int frontend_admit(const ankah_request *request, const char *host,
                          const char *direct_peer, int *kind, int *proved,
                          int *crawler, int *bing_claim) {
    char resolved[64];
    unsigned int i;
    int status = 0, rate_result = 0;
    for (i = 0; i < request->count; ++i) {
        if (same_ascii(request->headers[i].name, "X-Ankah-Internal-Rate-Checked") ||
            same_ascii(request->headers[i].name, "X-Ankah-Internal-Proved") ||
            same_ascii(request->headers[i].name, "X-Ankah-Internal-Crawler-Slot")) {
            status = 400;
            break;
        }
    }
    if (!status && ankah_resolve_client_ip(request, direct_peer,
            config.trusted_proxies, config.trusted_proxy_count,
            resolved, sizeof(resolved)) != 0) status = 400;
    if (!status && (!host || !same_ascii(host, config.public_host))) status = 421;
    if (!status) {
        *proved = request_proved(request);
        *crawler = ankah_google_crawler_is_known(resolved);
        *bing_claim = !*crawler && claims_bingbot(request);
        if (*crawler) *proved = 1;
        *kind = request_rate_class(request, *proved, *crawler || *bing_claim);
        if (!*bing_claim) rate_result = allow_rate((rate_class)*kind, resolved);
        if (rate_result) status = 429;
    }
    if (status) {
        ankah_stats_add(ANKAH_STAT_requests, 1);
        ankah_stats_add(ANKAH_STAT_responses_4xx, 1);
        if (rate_result) {
            ankah_stats_add(ANKAH_STAT_rate_limited, 1);
            ankah_stats_add(*kind == RATE_PROTECTED ? ANKAH_STAT_rate_limited_protected :
                            ANKAH_STAT_rate_limited_anonymous, 1);
        }
    }
    return status;
}

static int allowed(const ankah_request *request, int proved, int crawler) {
    unsigned int i;
    if (proved || crawler) return 1;
    for (i = 0; i < config.allow_count; ++i) {
        if (prefix(request->target, config.allow[i])) return 1;
    }
    return 0;
}

static void release_crawler_slot(connection *c) {
    if (!c->crawler_slot) return;
    c->crawler_slot = 0;
    ankah_crawler_release();
}

static void release_external_crawler_slot(connection *c) {
    if (!c->external_crawler_slot_id) return;
    ankah_frontend_release_crawler_slot(c->external_crawler_slot_id);
    c->external_crawler_slot_id = 0;
}

static void on_bingbot_verified(void *data, int verified) {
    connection *c = data;
    if (c->closed) return;
    c->bing_pending = 0;
    c->bing_checked = 1;
    c->crawler = verified;
    if (verified) c->proved = 1;
    else {
        release_crawler_slot(c);
        release_external_crawler_slot(c);
    }
    handle_initial(c);
}

/* Returns 1 while a Bing verification is in progress, -1 after replying, and
 * 0 when crawler classification is complete. */
static int classify_crawler(connection *c, int preadmitted) {
    int verified;
    if (preadmitted || c->crawler || c->bing_checked) return 0;
    if (ankah_google_crawler_is_known(c->peer_ip)) {
        c->crawler = 1;
        c->proved = 1;
        return 0;
    }
    if (!claims_bingbot(&c->request)) return 0;
    if (!c->external_crawler_slot_id && ankah_crawler_acquire() != 0) {
        respond(c, 429, "Too Many Requests", "text/plain",
                "Crawler concurrency exceeded\n", "Retry-After: 1\r\n");
        return -1;
    }
    if (!c->external_crawler_slot_id) c->crawler_slot = 1;
    if (ankah_bingbot_cache_lookup(c->peer_ip, &verified)) {
        c->bing_checked = 1;
        c->crawler = verified;
        if (verified) c->proved = 1;
        else {
            release_crawler_slot(c);
            release_external_crawler_slot(c);
        }
        return 0;
    }
    c->bing_pending = 1;
    if (ankah_bingbot_verify_start(config.loop, c->peer_ip,
                                   on_bingbot_verified, c) != 0) {
        c->bing_pending = 0;
        release_crawler_slot(c);
        release_external_crawler_slot(c);
        respond(c, 503, "Service Unavailable", "text/plain",
                "Crawler verification unavailable\n", "Retry-After: 1\r\n");
        return -1;
    }
    uv_read_stop((uv_stream_t *)&c->client);
    return 1;
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

static int render_script(const char *challenge, ankah_language language,
                         char *out, size_t capacity) {
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
        } else if (prefix(source, "@ANKAH_LANG@")) {
            replacement = ankah_language_tag(language);
            amount = strlen("@ANKAH_LANG@");
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

static int command_line_client(const ankah_request *request) {
    const char *agent = ankah_header_value(request, "User-Agent");
    return agent && (prefix(agent, "curl/") || prefix(agent, "Wget/"));
}

static int curl_instructions(ankah_language language, const char *message, const char *challenge,
                             char *out, size_t capacity) {
    int length = snprintf(out, capacity,
                          "%s%s%s"
                          "Linux/macOS: curl -fsSL '%s/ankah/challenge/%s' | bash\n"
                          "Windows: curl.exe -fsSL -o ankah.cmd '%s/ankah/challenge/%s' && ankah.cmd\n",
                          ankah_language_message(language, message), *message ? "\n" : "",
                          ankah_language_message(language, "Ankah challenge required.\n"),
                          config.public_origin, challenge, config.public_origin, challenge);
    return length < 0 || (size_t)length >= capacity ? -1 : 0;
}

static void respond_curl_challenge(connection *c, int status, const char *reason,
                                   const char *message, int redirect) {
    char challenge[ANKAH_CHALLENGE_TEXT_MAX], body[4096], extra[512] = "";
    ankah_language language = ankah_language_select(&c->request);
    int length;
    if (ankah_issue_challenge(config.secret, config.public_host,
                              (uint64_t)time(NULL), 18, challenge) != 0) {
        respond(c, 503, "Unavailable", "text/plain", "Challenge unavailable\n", NULL);
        return;
    }
    if (curl_instructions(language, message, challenge, body, sizeof(body)) != 0) {
        close_connection(c); return;
    }
    if (redirect) {
        length = snprintf(extra, sizeof(extra),
                          "Location: /ankah/blocked/run-ankah-challenge-%s\r\n", challenge);
        if (length < 0 || (size_t)length >= sizeof(extra)) { close_connection(c); return; }
    }
    tally(c, ANKAH_STAT_challenges_issued, 1);
    respond(c, status, reason, "text/plain; charset=utf-8", body, extra);
}

/* Refuses a request from a client that has not passed the challenge and
 * points it at the unlock page, returning to the page that sent it. */
static void respond_unlock_required(connection *c, int status, const char *reason,
                                    const char *message, const char *extra) {
    char return_path[MAX_RETURN_PATH + 1];
    char link[sizeof(config.public_origin) + ANKAH_MAX_TARGET];
    char escaped[sizeof(link) * 6];
    char body[sizeof(escaped) + 1024];
    char headers[512];
    ankah_language language = ankah_language_select(&c->request);
    int length;
    message = ankah_language_message(language, message);
    if (command_line_client(&c->request)) {
        respond_curl_challenge(c, status, reason, message, 0);
        return;
    }
    referer_return_path(&c->request, return_path, sizeof(return_path));
    if (unlock_url(return_path, link, sizeof(link)) != 0) { close_connection(c); return; }
    if (!accepts_html(&c->request)) {
        length = snprintf(body, sizeof(body), "%s\n%s%s\n", message,
                          ankah_language_message(language, "Unlock: "), link);
        if (length < 0 || (size_t)length >= sizeof(body)) { close_connection(c); return; }
        respond(c, status, reason, "text/plain", body, extra);
        return;
    }
    if (html_escape(link, escaped, sizeof(escaped)) != 0) { close_connection(c); return; }
    length = snprintf(body, sizeof(body),
        "<!doctype html><html lang=%s><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>%s</title>"
        "<style>html,body{margin:0;min-height:100%%;font:16px system-ui;background:#101929;color:#f4f7fb}"
        "main{max-width:38rem;margin:5vh auto;padding:2rem;text-align:center;background:#18253b;border-radius:1rem}"
        "a{display:inline-block;padding:.7rem 1.5rem;background:#f4f7fb;color:#101929;"
        "border-radius:.4rem;text-decoration:none}</style>"
        "<main><h1>%s</h1><p>%s</p><p><a href='%s'>%s</a></p></main></html>",
        ankah_language_tag(language),
        ankah_language_message(language, "Unlock required"),
        ankah_language_message(language, "Unlock required"), message, escaped,
        ankah_language_message(language, "Unlock"));
    if (length < 0 || (size_t)length >= sizeof(body)) { close_connection(c); return; }
    length = snprintf(headers, sizeof(headers),
                      "%sContent-Security-Policy: default-src 'none'; "
                      "style-src 'unsafe-inline'; frame-ancestors 'none'\r\n",
                      extra ? extra : "");
    if (length < 0 || (size_t)length >= sizeof(headers)) { close_connection(c); return; }
    respond(c, status, reason, "text/html; charset=utf-8", body, headers);
}

#define CHALLENGE_TEXT_ENTRY(name) \
    "<span data-name=\"" name "\"><!--#echo var=\"" name "\" --></span>"
static const char challenge_text_source[] =
    "<div id=\"challenge-text\" hidden>"
    CHALLENGE_TEXT_ENTRY("challenge_progress")
    CHALLENGE_TEXT_ENTRY("challenge_browser_unsupported")
    CHALLENGE_TEXT_ENTRY("challenge_search_exhausted")
    CHALLENGE_TEXT_ENTRY("challenge_worker_failed")
    CHALLENGE_TEXT_ENTRY("challenge_startup_timeout")
    CHALLENGE_TEXT_ENTRY("challenge_invalid")
    CHALLENGE_TEXT_ENTRY("challenge_passed_continuing")
    CHALLENGE_TEXT_ENTRY("challenge_passed_mobile")
    CHALLENGE_TEXT_ENTRY("challenge_answer_rejected")
    CHALLENGE_TEXT_ENTRY("challenge_failed")
    CHALLENGE_TEXT_ENTRY("challenge_solver_unavailable")
    CHALLENGE_TEXT_ENTRY("challenge_invalid_solver")
    CHALLENGE_TEXT_ENTRY("challenge_invalid_solver_memory")
    CHALLENGE_TEXT_ENTRY("challenge_solver_range_exhausted")
    "</div>";
#undef CHALLENGE_TEXT_ENTRY

static int render_challenge_text(ankah_language language, char *out, size_t capacity) {
    size_t written;
    if (ankah_language_render_html(language,
            (const unsigned char *)challenge_text_source,
            sizeof(challenge_text_source) - 1, (unsigned char *)out,
            capacity - 1, &written, ankah_language_text) != 0) return -1;
    out[written] = 0;
    return 0;
}

static void render_gate(connection *c, ankah_session *session) {
    char body[8192], extra[512], action[ANKAH_MAX_TARGET * 6], hidden[128];
    char illustration[160], challenge_js[160];
    char worker_js[160] = "", wasm_path[160] = "";
    char challenge_text[4096];
    ankah_language language = ankah_language_select(&c->request);
    int n;
    if (session->is_post) tally(c, ANKAH_STAT_posts_saved, 1);
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
    if (render_challenge_text(language, challenge_text, sizeof(challenge_text)) != 0) {
        close_connection(c); return;
    }
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
        "<!doctype html><html lang=%s><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>%s</title>"
        "<style>html,body{margin:0;min-height:100%%;font:16px system-ui;background:#101929;color:#f4f7fb}"
        "main{max-width:38rem;margin:5vh auto;padding:2rem;text-align:center;background:#18253b;border-radius:1rem}"
        "img{height:auto}#phone{width:100px}#qr{width:220px;background:white;padding:8px}"
        "#phone-help{display:flex;align-items:center;justify-content:center;gap:1rem;flex-wrap:wrap}"
        "button{padding:.7rem 1.5rem;font:inherit;cursor:pointer}"
        "</style><body data-challenge='%s' data-session='%s' data-worker='%s' data-wasm='%s'>"
        "<main><h1>%s</h1><p>%s</p>"
        "<output id=progress>%s</output>"
        "<section id=phone-panel><h2>%s</h2>"
        "<div id=phone-help><img id=phone src='%s' alt='%s'>"
        "<img id=qr src='/ankah/qr/%s.png' alt='%s'></div>"
        "<p>%s</p></section>"
        "<form id=finish method=%s action='%s'>%s<button type=submit>%s</button></form>"
        "</main>%s<script src='%s'></script></body></html>",
        ankah_language_tag(language),
        ankah_language_message(language, "Checking your browser"),
        session->challenge, session->id, worker_js, wasm_path,
        ankah_language_message(language, "Checking your browser"),
        ankah_language_message(language, "Solving a short proof of work."),
        ankah_language_message(language, "Starting challenge..."),
        ankah_language_message(language, "Don't have JavaScript? Scan here."),
        illustration, ankah_language_message(language, "Phone scanning a code"),
        session->id, ankah_language_message(language, "QR code to solve on your phone"),
        ankah_language_message(language, "After solving on your phone, click Finished here."),
        session->is_post ? "post" : "get",
        action, hidden, ankah_language_message(language, "Finished"), challenge_text,
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
    if (command_line_client(&c->request)) {
        respond_curl_challenge(c, 302, "Found", "", 1);
    } else {
        if (strcmp(c->request.method, "GET") != 0 &&
            strcmp(c->request.method, "POST") != 0) {
            respond_unlock_required(c, 405, "Method Not Allowed",
                                    "Unlock, then retry this method.",
                                    "Allow: GET, POST\r\n");
            return;
        }
        ankah_session *session = ankah_session_new_with_proof(config.secret,
            config.public_host, (uint64_t)time(NULL), &c->request, c->peer_ip, c->proved);
        size_t end = header_end(c->initial, c->initial_size);
        if (!session) {
            tally(c, ANKAH_STAT_challenge_session_rejected, 1);
            respond(c, 503, "Unavailable", "text/plain", "Challenge capacity reached\n", NULL);
            return;
        }
        tally(c, ANKAH_STAT_challenges_issued, 1);
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

/* Always issues a fresh challenge, even to a client that already passed one,
 * and returns to a local path once it is solved. */
static void handle_unlock(connection *c) {
    const char *query = c->request.target + strlen(UNLOCK_PATH);
    const char *return_path = "/";
    ankah_session *session;
    if (*query) {
        if (!prefix(query, "?return=") || !valid_return_path(query + strlen("?return="))) {
            respond(c, 400, "Bad Request", "text/plain", "Invalid return path\n", NULL);
            return;
        }
        return_path = query + strlen("?return=");
    }
    if (command_line_client(&c->request)) {
        respond_curl_challenge(c, 302, "Found", "", 1);
        return;
    }
    session = ankah_session_new_with_proof(config.secret, config.public_host,
                                (uint64_t)time(NULL), &c->request, c->peer_ip, c->proved);
    if (!session) {
        tally(c, ANKAH_STAT_challenge_session_rejected, 1);
        respond(c, 503, "Unavailable", "text/plain", "Challenge capacity reached\n", NULL);
        return;
    }
    strcpy(session->target, return_path);
    tally(c, ANKAH_STAT_challenges_issued, 1);
    render_gate(c, session);
}

static void handle_internal(connection *c) {
    const char *target = c->request.target;
    const char *host = config.public_host;
    if ((strcmp(target, UNLOCK_PATH) == 0 || prefix(target, UNLOCK_PATH "?")) &&
        strcmp(c->request.method, "GET") == 0) {
        handle_unlock(c);
        return;
    }
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
        char body[8192], challenge_text[4096];
        char script[160], worker_js[160] = "", wasm_path[160] = "";
        ankah_language language = ankah_language_select(&c->request);
        int n;
        if (!session || asset_path(3, script, sizeof(script)) != 0) {
            respond(c, 404, "Not Found", "text/plain", "Challenge expired\n", NULL); return;
        }
        tally(c, ANKAH_STAT_qr_scans, 1);
#if ANKAH_HAS_WASM
        if (asset_path(7, worker_js, sizeof(worker_js)) != 0 ||
            asset_path(8, wasm_path, sizeof(wasm_path)) != 0) {
            close_connection(c); return;
        }
#endif
        if (render_challenge_text(language, challenge_text,
                                  sizeof(challenge_text)) != 0) {
            close_connection(c); return;
        }
        if (ankah_session_solved(session, (uint64_t)time(NULL))) {
            n = snprintf(body, sizeof(body),
                "<!doctype html><html lang=%s><meta charset=utf-8><title>%s</title>"
                "<p>%s</p>", ankah_language_tag(language),
                ankah_language_message(language, "Finished"),
                ankah_language_message(language,
                    "Challenge passed. Click Finished on the original page."));
            if (n < 0 || (size_t)n >= sizeof(body)) { close_connection(c); return; }
            respond(c, 200, "OK", "text/html; charset=utf-8", body, NULL);
            return;
        }
        n = snprintf(body, sizeof(body),
            "<!doctype html><html lang=%s><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><body data-challenge='%s' data-session='%s' "
            "data-worker='%s' data-wasm='%s' data-mobile=1>"
            "<main><h1>%s</h1><output id=progress>%s</output>"
            "<p>%s</p></main>%s<script src='%s'></script></body></html>",
            ankah_language_tag(language),
            ankah_language_message(language, "Solve challenge"),
            session->challenge, session->id, worker_js, wasm_path,
            ankah_language_message(language, "Solve challenge"),
            ankah_language_message(language, "Starting..."),
            ankah_language_message(language,
                "When complete, click Finished on the original page."),
            challenge_text, script);
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
            tally(c, ANKAH_STAT_challenges_failed, 1);
            abuse_event(c, ANKAH_ABUSE_INVALID_PROOF, NULL);
            respond(c, 400, "Bad Request", "text/plain", "Invalid answer\n", NULL); return;
        }
        memcpy(key, target + strlen("/ankah/answer/"), 32); key[32] = 0;
        session = ankah_session_find(key, (uint64_t)time(NULL));
        if (decimal_u64(answer + 8, &counter) != 0 || !session ||
            ankah_check_answer(config.secret, host, (uint64_t)time(NULL),
                               session->challenge, counter) != 0 ||
            ankah_session_solve(session, (uint64_t)time(NULL)) != 0) {
            tally(c, ANKAH_STAT_challenges_failed, 1);
            abuse_event(c, ANKAH_ABUSE_INVALID_PROOF, NULL);
            respond(c, 403, "Forbidden", "text/plain", "Invalid answer\n", NULL); return;
        }
        tally(c, ANKAH_STAT_challenges_solved, 1);
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
        char script[8192];
        if (strlen(challenge) >= ANKAH_CHALLENGE_TEXT_MAX ||
            strspn(challenge, "0123456789abcdef.") != strlen(challenge) ||
            render_script(challenge, ankah_language_select(&c->request),
                          script, sizeof(script)) != 0) {
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
        if (strlen(challenge) >= ANKAH_CHALLENGE_TEXT_MAX ||
            strspn(challenge, "0123456789abcdef.") != strlen(challenge)) {
            respond(c, 400, "Bad Request", "text/plain", "Invalid challenge\n", NULL);
            return;
        }
        if (curl_instructions(ankah_language_select(&c->request), "",
                              challenge, body, sizeof(body)) != 0) {
            close_connection(c); return;
        }
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
            tally(c, ANKAH_STAT_challenges_failed, 1);
            abuse_event(c, ANKAH_ABUSE_INVALID_PROOF, NULL);
            respond(c, 403, "Forbidden", "text/plain", "Invalid challenge answer\n", NULL);
            return;
        }
        tally(c, ANKAH_STAT_passes_issued, 1);
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
        if (!ankah_header_is(&request->headers[i], ANKAH_HEADER_CONNECTION)) continue;
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
    unsigned char kind = ankah_header_effective_kind(header);
    if (kind == ANKAH_HEADER_HOST || kind == ANKAH_HEADER_CONTENT_LENGTH) return 0;
    if (c->request.chunked && (kind == ANKAH_HEADER_TRANSFER_ENCODING ||
                               kind == ANKAH_HEADER_TRAILER)) return 0;
    if (c->websocket && kind == ANKAH_HEADER_UPGRADE) return 0;
    if (kind == ANKAH_HEADER_CONNECTION || kind == ANKAH_HEADER_PROXY_CONNECTION ||
        kind == ANKAH_HEADER_PROXY_AUTHORIZATION || kind == ANKAH_HEADER_KEEP_ALIVE ||
        kind == ANKAH_HEADER_TE || kind == ANKAH_HEADER_TRAILER ||
        kind == ANKAH_HEADER_TRANSFER_ENCODING || kind == ANKAH_HEADER_UPGRADE ||
        kind == ANKAH_HEADER_FORWARDED || kind == ANKAH_HEADER_X_REAL_IP ||
        starts_ascii(header->name, "X-Ankah-Internal-") ||
        starts_ascii(header->name, "X-Forwarded-") ||
        (c->replaying && kind == ANKAH_HEADER_EXPECT)) return 1;
    return connection_names_header(&c->request, header->name);
}

static int prepare_client_ip(connection *c) {
    char direct[64], resolved[64];
    const char *key = NULL, *peer = NULL;
    unsigned int key_count = 0, peer_count = 0, i;
    strcpy(direct, c->peer_ip);
    for (i = 0; i < c->request.count; ++i) {
        const ankah_header *header = &c->request.headers[i];
        if (ankah_header_is(header, ANKAH_HEADER_X_ANKAH_INTERNAL_KEY)) {
            key = header->value;
            ++key_count;
        } else if (ankah_header_is(header, ANKAH_HEADER_X_ANKAH_INTERNAL_PEER)) {
            peer = header->value;
            ++peer_count;
        }
    }
    if (c->internal) {
        if (key_count != 1 || peer_count != 1 ||
            strcmp(key, config.internal_key) != 0 ||
            ankah_normalize_ip(peer, direct, sizeof(direct)) != 0) return -1;
    }
    if (ankah_resolve_client_ip(&c->request, direct,
                                config.trusted_proxies, config.trusted_proxy_count,
                                resolved, sizeof(resolved)) != 0) return -1;
    strcpy(c->direct_peer_ip, direct);
    c->trusted_direct_peer = !c->internal && ankah_peer_is_trusted(
        c->direct_peer_ip, config.trusted_proxies, config.trusted_proxy_count);
    strcpy(c->peer_ip, resolved);
    return 0;
}

/* The front end either charges a request or transfers its crawler slot. */
static int internal_admission(connection *c, int *proved) {
    unsigned int i, checked_count = 0, proof_count = 0, slot_count = 0;
    const char *checked = NULL, *proof = NULL, *slot = NULL;
    uint64_t slot_id = 0;
    if (!c->internal) return 0;
    for (i = 0; i < c->request.count; ++i) {
        if (same_ascii(c->request.headers[i].name, "X-Ankah-Internal-Rate-Checked")) {
            checked = c->request.headers[i].value;
            ++checked_count;
        } else if (same_ascii(c->request.headers[i].name, "X-Ankah-Internal-Proved")) {
            proof = c->request.headers[i].value;
            ++proof_count;
        } else if (same_ascii(c->request.headers[i].name, "X-Ankah-Internal-Crawler-Slot")) {
            slot = c->request.headers[i].value;
            ++slot_count;
        }
    }
    if (slot_count) {
        if (slot_count != 1 || decimal_u64(slot, &slot_id) != 0 ||
            !slot_id || checked_count || proof_count ||
            !claims_bingbot(&c->request)) return -1;
        c->external_crawler_slot_id = slot_id;
        return 0;
    }
    if (!checked_count && !proof_count) return 0;
    if (checked_count != 1 || proof_count != 1 || strcmp(checked, "1") != 0 ||
        (strcmp(proof, "0") != 0 && strcmp(proof, "1") != 0)) return -1;
    *proved = strcmp(proof, "1") == 0;
    return 1;
}

static int language_already_logged(const connection *c) {
    const char *value = NULL;
    unsigned int count = 0, i;
    for (i = 0; i < c->request.count; ++i) {
        if (same_ascii(c->request.headers[i].name,
                       "X-Ankah-Internal-Language-Logged")) {
            value = c->request.headers[i].value;
            ++count;
        }
    }
    return c->internal && count == 1 && strcmp(value, "1") == 0;
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

static void upstream_final_start(connection *c) {
    c->upstream_final_started = 1;
    c->reply_deadline_ns = 0;
}

static int upstream_status_complete(llhttp_t *parser) {
    connection *c = parser->data;
    if (llhttp_get_status_code(parser) >= 200) upstream_final_start(c);
    return 0;
}

static void on_connected(uv_connect_t *request, int status) {
    connection *c = (connection *)request->data;
    char head[ANKAH_HEADER_LIMIT + 1024];
    size_t end;
    int head_size;
    if (status < 0 || c->closed) {
        if (!c->closed) {
            tally(c, ANKAH_STAT_upstream_failures, 1);
            respond(c, 502, "Bad Gateway", "text/plain", "Upstream unavailable\n", NULL);
        }
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
    llhttp_settings_init(&c->upstream_response_settings);
    c->upstream_response_settings.on_status_complete = upstream_status_complete;
    llhttp_init(&c->upstream_response_parser, HTTP_RESPONSE,
                &c->upstream_response_settings);
    c->upstream_response_parser.data = c;
    if (c->websocket) tally(c, ANKAH_STAT_websocket_tunnels, 1);
    if (uv_read_start((uv_stream_t *)&c->upstream, allocate_read, on_upstream_read) != 0 ||
        (!c->replaying && !request_body_complete(c) &&
         uv_read_start((uv_stream_t *)&c->client, allocate_read, on_client_read) != 0))
        close_connection(c);
}

static int connect_upstream(connection *c) {
    struct sockaddr_storage address;
    int result;
    if (socket_address(config.upstream_ip, config.upstream_port, &address) != 0) return -1;
    if (uv_tcp_init(config.loop, &c->upstream) != 0) return -1;
    c->upstream_initialized = 1;
    c->upstream.data = c;
    ++c->handles;
    c->connect_request.data = c;
    result = uv_tcp_connect(&c->connect_request, &c->upstream,
                            (const struct sockaddr *)&address, on_connected);
    return result;
}

static int start_upstream(connection *c) {
    int result;
    tally(c, ANKAH_STAT_upstream_requests, 1);
    c->upstream_started_ns = uv_hrtime();
    result = connect_upstream(c);
    if (result != 0) tally(c, ANKAH_STAT_upstream_failures, 1);
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
    tally(c, ANKAH_STAT_posts_replayed, 1);
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

static void stats_sample(uint64_t wall, ankah_session_totals *sessions) {
    ankah_stats_roll(wall);
    ankah_session_count(wall, sessions);
    ankah_stats_max(ANKAH_STAT_peak_connections, config.connections);
    ankah_stats_max(ANKAH_STAT_peak_sessions, sessions->active);
    ankah_stats_max(ANKAH_STAT_peak_pending_bytes, sessions->pending_bytes);
}

/* The comparison time does not depend on how much of the token matches. */
static int dashboard_token_matches(const ankah_request *request, int allow_session) {
    const char *value = ankah_header_value(request, "Authorization");
    unsigned char given[ANKAH_SECRET_SIZE];
    unsigned int difference = 0;
    size_t i, j;
    uint64_t now = (uint64_t)time(NULL);
    if (!value || !starts_ascii(value, "Bearer ")) return 0;
    value += strlen("Bearer ");
    if (strlen(value) != ANKAH_SECRET_SIZE * 2) return 0;
    for (i = 0; i < ANKAH_SECRET_SIZE; ++i) {
        int high = hex_value(value[i * 2]);
        int low = hex_value(value[i * 2 + 1]);
        if (high < 0 || low < 0) return 0;
        given[i] = (unsigned char)((high << 4) | low);
    }
    for (i = 0; i < ANKAH_SECRET_SIZE; ++i)
        difference |= (unsigned int)(given[i] ^ config.dashboard_token[i]);
    if (difference == 0) return 1;
    if (!allow_session) return 0;
    for (j = 0; j < DASHBOARD_SESSIONS; ++j) {
        difference = 0;
        for (i = 0; i < ANKAH_SECRET_SIZE; ++i)
            difference |= (unsigned int)(given[i] ^ config.dashboard_sessions[j].token[i]);
        if (difference == 0 && config.dashboard_sessions[j].expires > now) return 1;
    }
    return 0;
}

static int dashboard_totp_secret(unsigned char secret[20]) {
    static const unsigned char label[] = "ankah dashboard totp v1";
    unsigned char digest[32];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || mbedtls_md_hmac(md, config.dashboard_token, ANKAH_SECRET_SIZE,
                              label, sizeof(label) - 1, digest) != 0) return -1;
    memcpy(secret, digest, 20);
    memset(digest, 0, sizeof(digest));
    return 0;
}

static int dashboard_totp_matches(const char *code, uint64_t now, uint64_t *step) {
    unsigned char secret[20], counter[8], digest[20];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    uint64_t current = now / 30;
    int offset, i;
    unsigned int given = 0;
    if (!code || strlen(code) != 6 || !md || dashboard_totp_secret(secret) != 0) return 0;
    for (i = 0; i < 6; ++i) {
        if (code[i] < '0' || code[i] > '9') return 0;
        given = given * 10 + (unsigned int)(code[i] - '0');
    }
    for (offset = -1; offset <= 1; ++offset) {
        uint64_t candidate;
        unsigned int value, position;
        if (offset < 0 && current == 0) continue;
        candidate = offset < 0 ? current - 1 : current + (unsigned int)offset;
        for (i = 7; i >= 0; --i) {
            counter[i] = (unsigned char)candidate;
            candidate >>= 8;
        }
        if (mbedtls_md_hmac(md, secret, sizeof(secret), counter, sizeof(counter), digest) != 0)
            return 0;
        position = digest[19] & 15;
        value = (((unsigned int)digest[position] & 127) << 24) |
                ((unsigned int)digest[position + 1] << 16) |
                ((unsigned int)digest[position + 2] << 8) | digest[position + 3];
        if (value % 1000000 == given) {
            *step = offset < 0 ? current - 1 : current + (unsigned int)offset;
            return 1;
        }
    }
    return 0;
}

static void dashboard_totp_base32(char output[33]) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned char secret[20];
    unsigned int bits = 0, buffer = 0;
    size_t i, used = 0;
    if (dashboard_totp_secret(secret) != 0) { output[0] = 0; return; }
    for (i = 0; i < sizeof(secret); ++i) {
        buffer = (buffer << 8) | secret[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output[used++] = alphabet[(buffer >> bits) & 31];
        }
    }
    output[used] = 0;
}

static void json_pair(ankah_text *text, const char *name, uint64_t value) {
    ankah_text_string(text, "\"");
    ankah_text_string(text, name);
    ankah_text_string(text, "\":");
    ankah_text_u64(text, value);
}

/* Takes ownership of the text buffer. */
static shared_body *body_from_text(ankah_text *text) {
    shared_body *body;
    if (text->failed || !text->size) {
        ankah_text_free(text);
        return NULL;
    }
    body = (shared_body *)calloc(1, sizeof(*body));
    if (!body) {
        ankah_text_free(text);
        return NULL;
    }
    body->data = text->data;
    body->size = text->size;
    body->pins = 1;
    return body;
}

static void metric_header(ankah_text *text, const char *name,
                          const char *help, const char *type) {
    ankah_text_string(text, "# HELP ");
    ankah_text_string(text, name);
    ankah_text_string(text, " ");
    ankah_text_string(text, help);
    ankah_text_string(text, "\n# TYPE ");
    ankah_text_string(text, name);
    ankah_text_string(text, " ");
    ankah_text_string(text, type);
    ankah_text_string(text, "\n");
}

static void metric_u64(ankah_text *text, const char *name,
                       const char *help, const char *type, uint64_t value) {
    metric_header(text, name, help, type);
    ankah_text_string(text, name);
    ankah_text_string(text, " ");
    ankah_text_u64(text, value);
    ankah_text_string(text, "\n");
}

static void metric_milliseconds(ankah_text *text, const char *name, uint64_t value) {
    char fraction[5];
    int length;
    ankah_text_string(text, name);
    ankah_text_string(text, " ");
    ankah_text_u64(text, value / 1000);
    length = snprintf(fraction, sizeof(fraction), ".%03u", (unsigned int)(value % 1000));
    if (length != 4) text->failed = 1;
    else ankah_text_append(text, fraction, 4);
    ankah_text_string(text, "\n");
}

static shared_body *render_metrics(void) {
    typedef struct {
        unsigned int field;
        const char *name;
        const char *help;
    } counter_metric;
    static const counter_metric counters[] = {
        {ANKAH_STAT_client_bytes_in, "ankah_client_bytes_in_total",
         "Bytes received from public clients."},
        {ANKAH_STAT_client_bytes_out, "ankah_client_bytes_out_total",
         "Bytes sent to public clients."},
        {ANKAH_STAT_upstream_bytes_in, "ankah_upstream_bytes_in_total",
         "Bytes received from the application upstream."},
        {ANKAH_STAT_upstream_bytes_out, "ankah_upstream_bytes_out_total",
         "Bytes sent to the application upstream."},
        {ANKAH_STAT_accepted, "ankah_connections_accepted_total",
         "Public connections accepted by the gateway core."},
        {ANKAH_STAT_refused, "ankah_connections_refused_total",
         "Public connections refused at the connection limit."},
        {ANKAH_STAT_websocket_tunnels, "ankah_websocket_tunnels_total",
         "WebSocket tunnels opened."},
        {ANKAH_STAT_requests, "ankah_http_requests_total",
         "Public HTTP requests parsed."},
        {ANKAH_STAT_rate_limited, "ankah_rate_limited_requests_total",
         "Public requests rejected by rate limiting."},
        {ANKAH_STAT_rate_limited_anonymous, "ankah_anonymous_rate_limited_requests_total",
         "Anonymous requests rejected by request rate limiting."},
        {ANKAH_STAT_rate_limited_protected, "ankah_protected_rate_limited_requests_total",
         "Protected requests rejected by request rate limiting."},
        {ANKAH_STAT_anonymous_connection_rejected,
         "ankah_anonymous_connections_rejected_total",
         "Anonymous requests rejected at the connection occupancy limit."},
        {ANKAH_STAT_pending_connection_refused,
         "ankah_pending_connections_refused_total",
         "Connections refused at the pending header limit."},
        {ANKAH_STAT_challenge_session_rejected,
         "ankah_challenge_sessions_rejected_total",
         "Challenge sessions rejected at a capacity limit."},
        {ANKAH_STAT_challenges_issued, "ankah_challenges_issued_total",
         "Proof-of-work challenges issued."},
        {ANKAH_STAT_challenges_solved, "ankah_challenges_solved_total",
         "Proof-of-work challenges solved."},
        {ANKAH_STAT_challenges_failed, "ankah_challenges_failed_total",
         "Proof-of-work challenge answers rejected."},
        {ANKAH_STAT_passes_issued, "ankah_passes_issued_total",
         "Reusable passes issued."},
        {ANKAH_STAT_qr_scans, "ankah_challenge_qr_scans_total",
         "Challenge QR codes opened."},
        {ANKAH_STAT_posts_saved, "ankah_continuation_posts_saved_total",
         "POST requests saved for challenge continuation."},
        {ANKAH_STAT_posts_replayed, "ankah_continuation_posts_replayed_total",
         "Saved POST requests replayed."},
        {ANKAH_STAT_static_requests, "ankah_static_requests_total",
         "Requests handled by packaged static serving."},
        {ANKAH_STAT_static_bytes, "ankah_static_bytes_total",
         "Packaged static response body bytes sent."},
        {ANKAH_STAT_throttled_static_requests, "ankah_static_throttle_requests_total",
         "Packaged static responses admitted through the download throttle."},
        {ANKAH_STAT_throttled_static_bytes, "ankah_static_throttle_bytes_total",
         "Packaged static response body bytes admitted through the download throttle."},
        {ANKAH_STAT_throttle_queue_responses, "ankah_static_throttle_queue_responses_total",
         "Queue responses returned by the packaged static throttle."},
        {ANKAH_STAT_throttle_queued_requests, "ankah_static_throttle_queued_requests_total",
         "Packaged static responses admitted after waiting in the queue."},
        {ANKAH_STAT_cache_hits, "ankah_static_cache_hits_total",
         "Packaged static cache hits."},
        {ANKAH_STAT_cache_misses, "ankah_static_cache_misses_total",
         "Packaged static cache misses."},
        {ANKAH_STAT_upstream_requests, "ankah_upstream_requests_total",
         "Application upstream connection attempts."},
        {ANKAH_STAT_upstream_failures, "ankah_upstream_failures_total",
         "Application upstream connection failures."},
        {ANKAH_STAT_upstream_responses, "ankah_upstream_responses_total",
         "Application upstream responses observed."}
    };
    const ankah_stat_record *record;
    ankah_session_totals sessions;
    ankah_text text;
    uint64_t wall = (uint64_t)time(NULL);
    size_t i;
    stats_sample(wall, &sessions);
    throttle_prune_queue(uv_hrtime());
    record = ankah_stats_cumulative();
    ankah_text_init(&text);
    for (i = 0; i < sizeof(counters) / sizeof(counters[0]); ++i)
        metric_u64(&text, counters[i].name, counters[i].help, "counter",
                   record->v[counters[i].field]);
    metric_header(&text, "ankah_proxy_abuse_actions_total",
                  "Block actions sent to trusted proxies by reason.", "counter");
    for (i = 0; i < ANKAH_ABUSE_REASONS; ++i) {
        static const char *const reasons[] = {
            "invalid_proof", "client_rate", "path_scan", "body_stall"
        };
        ankah_text_string(&text, "ankah_proxy_abuse_actions_total{reason=\"");
        ankah_text_string(&text, reasons[i]);
        ankah_text_string(&text, "\"} ");
        ankah_text_u64(&text, ankah_abuse_signal_count(
            config.abuse_policy, (ankah_abuse_event)i));
        ankah_text_string(&text, "\n");
    }
    if (ankah_dots_enabled()) {
        ankah_dots_counters dots;
        ankah_dots_counters_get(&dots);
        metric_u64(&text, "ankah_dots_escalations_total",
                   "Clients that reached the DOTS escalation threshold.", "counter",
                   dots.escalations);
        metric_u64(&text, "ankah_dots_dropped_total",
                   "DOTS escalations that were not sent.", "counter", dots.dropped);
        metric_header(&text, "ankah_dots_operations_total",
                      "DOTS data channel operations by result.", "counter");
        for (i = 0; i < ANKAH_DOTS_OPS; ++i) {
            ankah_text_string(&text, "ankah_dots_operations_total{operation=\"");
            ankah_text_string(&text, ankah_dots_operation_name((int)i));
            ankah_text_string(&text, "\",result=\"ok\"} ");
            ankah_text_u64(&text, dots.ok[i]);
            ankah_text_string(&text, "\nankah_dots_operations_total{operation=\"");
            ankah_text_string(&text, ankah_dots_operation_name((int)i));
            ankah_text_string(&text, "\",result=\"error\"} ");
            ankah_text_u64(&text, dots.failed[i]);
            ankah_text_string(&text, "\n");
        }
        metric_u64(&text, "ankah_dots_active_acls",
                   "DOTS filtering ACLs currently installed by this process.", "gauge",
                   dots.active);
        metric_u64(&text, "ankah_dots_registered",
                   "Whether the DOTS client registration succeeded.", "gauge",
                   (uint64_t)dots.registered);
    }
    metric_header(&text, "ankah_http_responses_total",
                  "Public HTTP responses by status-code class.", "counter");
    for (i = 0; i < 4; ++i) {
        static const char *const classes[4] = {"2xx", "3xx", "4xx", "5xx"};
        ankah_text_string(&text, "ankah_http_responses_total{class=\"");
        ankah_text_string(&text, classes[i]);
        ankah_text_string(&text, "\"} ");
        ankah_text_u64(&text, record->v[ANKAH_STAT_responses_2xx + i]);
        ankah_text_string(&text, "\n");
    }
    metric_header(&text, "ankah_upstream_response_latency_seconds",
                  "Time to the first application upstream response byte.", "summary");
    metric_milliseconds(&text, "ankah_upstream_response_latency_seconds_sum",
                        record->v[ANKAH_STAT_upstream_latency_ms_total]);
    ankah_text_string(&text, "ankah_upstream_response_latency_seconds_count ");
    ankah_text_u64(&text, record->v[ANKAH_STAT_upstream_responses]);
    ankah_text_string(&text, "\n");
    metric_header(&text, "ankah_upstream_response_latency_peak_seconds",
                  "Peak time to the first application upstream response byte.", "gauge");
    metric_milliseconds(&text, "ankah_upstream_response_latency_peak_seconds",
                        record->v[ANKAH_STAT_upstream_latency_peak_ms]);
    metric_header(&text, "ankah_static_throttle_queue_wait_seconds",
                  "Time spent waiting for packaged static throttle admission.", "summary");
    metric_milliseconds(&text, "ankah_static_throttle_queue_wait_seconds_sum",
                        record->v[ANKAH_STAT_throttle_wait_ms_total]);
    ankah_text_string(&text, "ankah_static_throttle_queue_wait_seconds_count ");
    ankah_text_u64(&text, record->v[ANKAH_STAT_throttle_queued_requests]);
    ankah_text_string(&text, "\n");
    metric_header(&text, "ankah_static_throttle_queue_wait_peak_seconds",
                  "Peak packaged static throttle queue wait.", "gauge");
    metric_milliseconds(&text, "ankah_static_throttle_queue_wait_peak_seconds",
                        record->v[ANKAH_STAT_throttle_wait_ms_peak]);
    metric_u64(&text, "ankah_connections_current", "Current public connections.",
               "gauge", config.connections);
    metric_u64(&text, "ankah_tls_connections_current", "Current direct TLS connections.",
               "gauge", config.tls_certificate[0] ? ankah_frontend_connections() : 0);
    metric_u64(&text, "ankah_sessions_current", "Current challenge sessions.",
               "gauge", sessions.active);
    metric_u64(&text, "ankah_solved_sessions_current", "Current solved challenge sessions.",
               "gauge", sessions.solved);
    metric_u64(&text, "ankah_saved_posts_current", "Current saved POST requests.",
               "gauge", sessions.saved_posts);
    metric_u64(&text, "ankah_pending_bytes_current", "Current saved POST body bytes.",
               "gauge", sessions.pending_bytes);
    metric_u64(&text, "ankah_static_cache_bytes_current", "Current static cache bytes.",
               "gauge", config.static_cache_used);
    metric_u64(&text, "ankah_static_throttle_connections_current",
               "Current admitted packaged static throttle transfers.",
               "gauge", config.throttle_active);
    metric_u64(&text, "ankah_static_throttle_queue_current",
               "Current packaged static throttle queue depth.",
               "gauge", config.throttle_queue_count);
    metric_u64(&text, "ankah_connections_peak", "Peak public connections.", "gauge",
               record->v[ANKAH_STAT_peak_connections]);
    metric_u64(&text, "ankah_sessions_peak", "Peak challenge sessions.", "gauge",
               record->v[ANKAH_STAT_peak_sessions]);
    metric_u64(&text, "ankah_pending_bytes_peak", "Peak saved POST body bytes.", "gauge",
               record->v[ANKAH_STAT_peak_pending_bytes]);
    metric_u64(&text, "ankah_static_throttle_connections_peak",
               "Peak concurrent packaged static throttle transfers.", "gauge",
               record->v[ANKAH_STAT_peak_throttle_connections]);
    metric_u64(&text, "ankah_static_throttle_queue_peak",
               "Peak packaged static throttle queue depth.", "gauge",
               record->v[ANKAH_STAT_peak_throttle_queue]);
    metric_u64(&text, "ankah_connections_limit", "Configured public connection limit.",
               "gauge", MAX_CONNECTIONS);
    metric_u64(&text, "ankah_tls_connections_limit", "Configured direct TLS connection limit.",
               "gauge", config.tls_certificate[0] ? ANKAH_FRONTEND_MAX_CONNECTIONS : 0);
    metric_u64(&text, "ankah_sessions_limit", "Challenge session limit.",
               "gauge", sessions.capacity);
    metric_u64(&text, "ankah_pending_bytes_limit", "Saved POST body byte limit.",
               "gauge", sessions.pending_capacity);
    metric_u64(&text, "ankah_static_cache_bytes_limit", "Configured static cache byte limit.",
               "gauge", config.static_cache_limit);
    metric_u64(&text, "ankah_static_throttle_connections_limit",
               "Configured global packaged static throttle connection limit.",
               "gauge", config.throttle_prefix_count ? config.throttle_global_connections : 0);
    metric_u64(&text, "ankah_static_throttle_client_connections_limit",
               "Configured per-client packaged static throttle connection limit.",
               "gauge", config.throttle_prefix_count ? config.throttle_client_connections : 0);
    metric_u64(&text, "ankah_static_throttle_bytes_per_second_limit",
               "Configured global packaged static throttle byte rate.",
               "gauge", config.throttle_global_bytes_per_second);
    metric_u64(&text, "ankah_static_throttle_client_bytes_per_second_limit",
               "Configured per-client packaged static throttle byte rate.",
               "gauge", config.throttle_client_bytes_per_second);
    metric_u64(&text, "ankah_stats_epoch_seconds", "Statistics epoch as Unix time.",
               "gauge", ankah_stats_epoch());
    return body_from_text(&text);
}

static shared_body *render_schema(void) {
    ankah_text text;
    ankah_session_totals sessions;
    ankah_session_count((uint64_t)time(NULL), &sessions);
    ankah_text_init(&text);
    ankah_text_string(&text, "{\"v\":3,");
    ankah_stats_write_schema(&text);
    ankah_text_string(&text, ",\"limits\":{");
    json_pair(&text, "connections", MAX_CONNECTIONS);
    ankah_text_string(&text, ",");
    json_pair(&text, "tls_connections",
              config.tls_certificate[0] ? ANKAH_FRONTEND_MAX_CONNECTIONS : 0);
    ankah_text_string(&text, ",");
    json_pair(&text, "sessions", sessions.capacity);
    ankah_text_string(&text, ",");
    json_pair(&text, "pending_bytes", sessions.pending_capacity);
    ankah_text_string(&text, ",");
    json_pair(&text, "cache_bytes", config.static_cache_limit);
    ankah_text_string(&text, ",");
    json_pair(&text, "throttle_connections",
              config.throttle_prefix_count ? config.throttle_global_connections : 0);
    ankah_text_string(&text, ",");
    json_pair(&text, "throttle_client_connections",
              config.throttle_prefix_count ? config.throttle_client_connections : 0);
    ankah_text_string(&text, ",");
    json_pair(&text, "throttle_bytes_per_second",
              config.throttle_global_bytes_per_second);
    ankah_text_string(&text, ",");
    json_pair(&text, "throttle_client_bytes_per_second",
              config.throttle_client_bytes_per_second);
    ankah_text_string(&text, ",");
    json_pair(&text, "throttle_queue",
              config.throttle_prefix_count ? MAX_THROTTLE_QUEUE : 0);
    ankah_text_string(&text, ",");
    json_pair(&text, "top_connections", TOP_CONNECTIONS);
    ankah_text_string(&text, "}}");
    return body_from_text(&text);
}

static const char *connection_state(const connection *c) {
    if (c->websocket && c->forwarding) return "tunnel";
    if (c->forwarding) return "forwarding";
    if (c->upstream_initialized) return "connecting";
    if (c->segmented || c->asset_index >= 0) return "sending";
    if (c->capture_session || c->capture_continue) return "uploading";
    return c->request.method[0] ? "responding" : "reading";
}

static uint64_t connection_weight(const connection *c) {
    return c->bytes_in + c->bytes_out;
}

/* Only numbers, fixed words and address characters reach the output, so
 * nothing needs escaping. Request targets are deliberately left out. */
static void write_connection(ankah_text *text, const connection *c, uint64_t now_ms) {
    const char *ip = c->peer_ip;
    if (!ip[0] || strspn(ip, "0123456789abcdefABCDEF.:") != strlen(ip)) ip = "?";
    ankah_text_string(text, "{");
    json_pair(text, "id", c->id);
    ankah_text_string(text, ",\"ip\":\"");
    ankah_text_string(text, ip);
    ankah_text_string(text, "\",");
    json_pair(text, "age_ms", now_ms - c->accepted_ms);
    ankah_text_string(text, ",");
    json_pair(text, "in", c->bytes_in);
    ankah_text_string(text, ",");
    json_pair(text, "out", c->bytes_out);
    ankah_text_string(text, c->websocket ? ",\"ws\":true,\"state\":\"" :
                                           ",\"ws\":false,\"state\":\"");
    ankah_text_string(text, connection_state(c));
    ankah_text_string(text, "\"}");
}

static void write_top(ankah_text *text) {
    const connection *top[TOP_CONNECTIONS];
    const connection *c;
    size_t used = 0, i;
    uint64_t others = 0, other_in = 0, other_out = 0, now_ms = uv_now(config.loop);
    for (c = config.live_first; c; c = c->live_next) {
        size_t j;
        if (used == TOP_CONNECTIONS) {
            const connection *spill = c;
            if (connection_weight(c) > connection_weight(top[used - 1])) spill = top[--used];
            ++others;
            other_in += spill->bytes_in;
            other_out += spill->bytes_out;
            if (spill == c) continue;
        }
        for (j = used++; j > 0 && connection_weight(top[j - 1]) < connection_weight(c); --j)
            top[j] = top[j - 1];
        top[j] = c;
    }
    ankah_text_string(text, "\"top\":[");
    for (i = 0; i < used; ++i) {
        if (i) ankah_text_string(text, ",");
        write_connection(text, top[i], now_ms);
    }
    ankah_text_string(text, "],\"top_other\":{");
    json_pair(text, "count", others);
    ankah_text_string(text, ",");
    json_pair(text, "in", other_in);
    ankah_text_string(text, ",");
    json_pair(text, "out", other_out);
    ankah_text_string(text, "}");
}

static shared_body *render_live(void) {
    ankah_text text;
    ankah_session_totals sessions;
    uint64_t wall = (uint64_t)time(NULL);
    stats_sample(wall, &sessions);
    throttle_prune_queue(uv_hrtime());
    ankah_text_init(&text);
    ankah_text_string(&text, "{\"v\":3,");
    json_pair(&text, "now", wall);
    ankah_text_string(&text, ",");
    json_pair(&text, "sample_ms", uv_hrtime() / 1000000);
    ankah_text_string(&text, ",");
    ankah_stats_write_live(&text);
    ankah_text_string(&text, ",\"gauges\":{");
    json_pair(&text, "connections", config.connections);
    ankah_text_string(&text, ",");
    json_pair(&text, "tls_connections",
              config.tls_certificate[0] ? ankah_frontend_connections() : 0);
    ankah_text_string(&text, ",");
    json_pair(&text, "sessions", sessions.active);
    ankah_text_string(&text, ",");
    json_pair(&text, "solved_sessions", sessions.solved);
    ankah_text_string(&text, ",");
    json_pair(&text, "saved_posts", sessions.saved_posts);
    ankah_text_string(&text, ",");
    json_pair(&text, "pending_bytes", sessions.pending_bytes);
    ankah_text_string(&text, ",");
    json_pair(&text, "cache_bytes", config.static_cache_used);
    ankah_text_string(&text, ",");
    json_pair(&text, "throttle_connections", config.throttle_active);
    ankah_text_string(&text, ",");
    json_pair(&text, "throttle_queue", config.throttle_queue_count);
    ankah_text_string(&text, "},");
    write_top(&text);
    ankah_text_string(&text, "}");
    return body_from_text(&text);
}

/* One rendering serves every viewer polling within the cache window. */
static shared_body *live_body(void) {
    uint64_t now = uv_hrtime();
    if (!config.live_body || now - config.live_body_ns >= LIVE_CACHE_NS) {
        shared_body *fresh = render_live();
        if (!fresh) return NULL;
        body_release(config.live_body);
        config.live_body = fresh;
        config.live_body_ns = now;
    }
    ++config.live_body->pins;
    return config.live_body;
}

static shared_body *render_history(uint64_t hours, uint64_t days) {
    ankah_text text;
    ankah_session_totals sessions;
    uint64_t wall = (uint64_t)time(NULL);
    stats_sample(wall, &sessions);
    ankah_text_init(&text);
    ankah_text_string(&text, "{\"v\":3,");
    json_pair(&text, "now", wall);
    ankah_text_string(&text, ",");
    ankah_stats_write_history(&text,
                              hours < ANKAH_STAT_HOURS ? (size_t)hours : ANKAH_STAT_HOURS,
                              days < ANKAH_STAT_DAYS ? (size_t)days : ANKAH_STAT_DAYS);
    ankah_text_string(&text, "}");
    return body_from_text(&text);
}

static shared_body *render_export(uint64_t *exported_at) {
    ankah_text text;
    ankah_session_totals sessions;
    *exported_at = (uint64_t)time(NULL);
    stats_sample(*exported_at, &sessions);
    ankah_text_init(&text);
    ankah_stats_write_csv(&text, *exported_at);
    return body_from_text(&text);
}

static int history_query(const char *query, uint64_t *hours, uint64_t *days) {
    char value[24];
    while (query && *query) {
        const char *end = strchr(query, '&');
        size_t length = end ? (size_t)(end - query) : strlen(query), skip = 0;
        uint64_t *slot = NULL;
        if (length > 6 && strncmp(query, "hours=", 6) == 0) {
            slot = hours;
            skip = 6;
        } else if (length > 5 && strncmp(query, "days=", 5) == 0) {
            slot = days;
            skip = 5;
        }
        if (slot) {
            if (length - skip >= sizeof(value)) return -1;
            memcpy(value, query + skip, length - skip);
            value[length - skip] = 0;
            if (decimal_u64(value, slot) != 0) return -1;
        }
        query = end ? end + 1 : NULL;
    }
    return 0;
}

/* Takes over the caller's pin on the body. */
static void send_body(connection *c, shared_body *body, const char *type,
                      const char *extra) {
    char head[512];
    int length;
    c->body_pin = body;
    c->segmented = 1;
    length = snprintf(head, sizeof(head),
                      "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
                      "Content-Length: %zu\r\nCache-Control: no-store\r\n"
                      "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
                      "%sConnection: close\r\n\r\n", type, body->size,
                      extra ? extra : "");
    if (length < 0 || (size_t)length >= sizeof(head) ||
        static_add_segment(c, (const unsigned char *)body->data, body->size) != 0 ||
        queue_bytes(c, (uv_stream_t *)&c->client, NULL, head, (size_t)length, 0) != 0)
        close_connection(c);
}

static int same_path(const char *target, size_t length, const char *path) {
    return strlen(path) == length && strncmp(target, path, length) == 0;
}

/* Page files hold no statistics, so they need no token. */
static const static_asset *dashboard_page_asset(const char *target,
                                                ankah_language language) {
    static const char *const paths[DASHBOARD_ASSET_COUNT] = {
        "/", "/dashboard/dashboard.css", "/dashboard/dashboard.js",
        "/dashboard/d3-subset.min.js"
    };
    unsigned int i;
    if (strcmp(target, "/") == 0) return &config.dashboard_pages[language];
    for (i = 1; i < DASHBOARD_ASSET_COUNT; ++i)
        if (strcmp(target, paths[i]) == 0) return &config.dashboard_assets[i];
    if (strcmp(target, "/dashboard/particles.min.js") == 0) return &config.assets[1];
    if (strcmp(target, "/dashboard/particlejs.json") == 0) return &config.assets[2];
    return NULL;
}

static int dashboard_asset_language(const static_asset *asset,
                                    ankah_language *language) {
    unsigned int i;
    for (i = 0; i < ANKAH_LANGUAGE_COUNT; ++i) {
        if (asset == &config.dashboard_pages[i]) {
            *language = (ankah_language)i;
            return 1;
        }
    }
    return 0;
}

static void serve_dashboard_asset(connection *c, const static_asset *asset) {
    char head[1024];
    char language_headers[128] = "";
    ankah_language language;
    int page = dashboard_asset_language(asset, &language);
    int cached = etag_matches(&c->request, asset->etag);
    if (page) {
        int header_length = snprintf(language_headers, sizeof(language_headers),
            "Content-Language: %s\r\nVary: Accept-Language\r\n",
            ankah_language_tag(language));
        if (header_length < 0 || (size_t)header_length >= sizeof(language_headers)) {
            close_connection(c);
            return;
        }
    }
    int length = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Cache-Control: no-cache\r\nETag: %s\r\nX-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\n%s%sConnection: close\r\n\r\n",
        cached ? 304 : 200, cached ? "Not Modified" : "OK", asset->type, asset->size,
        asset->etag, language_headers,
        page ?
            "Content-Security-Policy: default-src 'none'; script-src 'self'; "
            "style-src 'self'; img-src 'self' blob:; connect-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'\r\n" : "");
    if (length < 0 || (size_t)length >= sizeof(head)) {
        close_connection(c);
        return;
    }
    if (!cached && strcmp(c->request.method, "HEAD") != 0 && asset->size) {
        if (static_add_segment(c, asset->data, asset->size) != 0) {
            close_connection(c);
            return;
        }
        c->segmented = 1;
    }
    if (queue_bytes(c, (uv_stream_t *)&c->client, NULL, head, (size_t)length,
                    !c->segmented) != 0) close_connection(c);
}

static void handle_dashboard(connection *c, size_t end, const char *target) {
    enum { UNKNOWN, SCHEMA, LIVE, HISTORY, EXPORT, RESET, METRICS, AUTH_QR,
           AUTH_LOGIN, AUTH_LOGOUT } route = UNKNOWN;
    const char *query = strchr(target, '?');
    size_t length = query ? (size_t)(query - target) : strlen(target);
    shared_body *body = NULL;
    uv_read_stop((uv_stream_t *)&c->client);
    if (c->request.chunked || c->request.content_length || c->initial_size != end ||
        ankah_header_value(&c->request, "Expect") || c->request.websocket) {
        respond(c, 400, "Bad Request", "text/plain", "Dashboard requests carry no body\n", NULL);
        return;
    }
    if (same_path(target, length, "/metrics")) route = METRICS;
    else if (same_path(target, length, "/auth/qr")) route = AUTH_QR;
    else if (same_path(target, length, "/auth/login")) route = AUTH_LOGIN;
    else if (same_path(target, length, "/auth/logout")) route = AUTH_LOGOUT;
    if (strncmp(target, "/stats/", 7) != 0 && route == UNKNOWN) {
        ankah_language language = ankah_language_select(&c->request);
        const static_asset *asset = dashboard_page_asset(target, language);
        if (!asset) {
            respond(c, 404, "Not Found", "text/plain", "Unknown dashboard path\n", NULL);
        } else if (strcmp(c->request.method, "GET") != 0 &&
                   strcmp(c->request.method, "HEAD") != 0) {
            respond(c, 405, "Method Not Allowed", "text/plain", "Use GET\n",
                    "Allow: GET, HEAD\r\n");
        } else serve_dashboard_asset(c, asset);
        return;
    }
    if (route != AUTH_LOGIN && !dashboard_token_matches(&c->request, route != AUTH_QR)) {
        respond(c, 401, "Unauthorized", "text/plain", "Dashboard token required\n",
                "WWW-Authenticate: Bearer realm=\"ankah\"\r\n");
        return;
    }
    if (route == AUTH_QR) {
        char secret[33], uri[160];
        unsigned char *png;
        size_t png_size;
        if (strcmp(c->request.method, "GET") != 0) {
            respond(c, 405, "Method Not Allowed", "text/plain", "Use GET\n", "Allow: GET\r\n");
            return;
        }
        dashboard_totp_base32(secret);
        if (!secret[0] || snprintf(uri, sizeof(uri),
                "otpauth://totp/Ankah:Dashboard?secret=%s&issuer=Ankah&algorithm=SHA1&digits=6&period=30",
                secret) >= (int)sizeof(uri) || ankah_qr_png(uri, &png, &png_size) != 0) {
            respond(c, 503, "Unavailable", "text/plain", "QR code unavailable\n", NULL);
            return;
        }
        respond_binary(c, "image/png", png, png_size);
        free(png);
        return;
    }
    if (route == AUTH_LOGIN) {
        const char *code = ankah_header_value(&c->request, "X-Ankah-Code");
        uint64_t now = (uint64_t)time(NULL), step = 0;
        size_t slot = 0, i;
        char reply[80], encoded[65];
        unsigned char random_token[32];
        if (strcmp(c->request.method, "POST") != 0) {
            respond(c, 405, "Method Not Allowed", "text/plain", "Use POST\n", "Allow: POST\r\n");
            return;
        }
        if (now >= config.dashboard_attempt_window + 60) {
            config.dashboard_attempt_window = now;
            config.dashboard_failed_attempts = 0;
        }
        if (config.dashboard_failed_attempts >= 5) {
            respond(c, 429, "Too Many Requests", "text/plain", "Try again later\n",
                    "Retry-After: 60\r\n");
            return;
        }
        if (!dashboard_totp_matches(code, now, &step) ||
            step <= config.dashboard_last_code_step) {
            ++config.dashboard_failed_attempts;
            respond(c, 401, "Unauthorized", "text/plain", "Invalid code\n", NULL);
            return;
        }
        for (i = 0; i < DASHBOARD_SESSIONS; ++i)
            if (config.dashboard_sessions[i].expires <= now) { slot = i; break; }
        if (i == DASHBOARD_SESSIONS) {
            for (i = 1; i < DASHBOARD_SESSIONS; ++i)
                if (config.dashboard_sessions[i].expires < config.dashboard_sessions[slot].expires)
                    slot = i;
        }
        if (ankah_random(random_token, sizeof(random_token)) != 0) {
            respond(c, 503, "Unavailable", "text/plain", "Session unavailable\n", NULL);
            return;
        }
        memcpy(config.dashboard_sessions[slot].token, random_token, sizeof(random_token));
        config.dashboard_sessions[slot].expires = now + DASHBOARD_SESSION_SECONDS;
        config.dashboard_last_code_step = step;
        config.dashboard_failed_attempts = 0;
        hex_encode(random_token, sizeof(random_token), encoded);
        snprintf(reply, sizeof(reply), "{\"token\":\"%s\"}", encoded);
        respond(c, 200, "OK", "application/json", reply, NULL);
        return;
    }
    if (route == AUTH_LOGOUT) {
        const char *value = ankah_header_value(&c->request, "Authorization");
        unsigned char given[32];
        size_t i, j;
        if (strcmp(c->request.method, "POST") != 0) {
            respond(c, 405, "Method Not Allowed", "text/plain", "Use POST\n", "Allow: POST\r\n");
            return;
        }
        if (value && starts_ascii(value, "Bearer ") && strlen(value + 7) == 64) {
            value += 7;
            for (i = 0; i < sizeof(given); ++i) {
                int high = hex_value(value[i * 2]), low = hex_value(value[i * 2 + 1]);
                if (high < 0 || low < 0) break;
                given[i] = (unsigned char)((high << 4) | low);
            }
            if (i == sizeof(given)) for (j = 0; j < DASHBOARD_SESSIONS; ++j) {
                unsigned int difference = 0;
                for (i = 0; i < sizeof(given); ++i)
                    difference |= (unsigned int)(given[i] ^ config.dashboard_sessions[j].token[i]);
                if (difference == 0) config.dashboard_sessions[j].expires = 0;
            }
        }
        respond(c, 204, "No Content", "application/json", "", NULL);
        return;
    }
    if (same_path(target, length, "/stats/schema")) route = SCHEMA;
    else if (same_path(target, length, "/stats/live")) route = LIVE;
    else if (same_path(target, length, "/stats/history")) route = HISTORY;
    else if (same_path(target, length, "/stats/export.csv")) route = EXPORT;
    else if (same_path(target, length, "/stats/reset")) route = RESET;
    if (route == UNKNOWN) {
        respond(c, 404, "Not Found", "text/plain", "Unknown statistics path\n", NULL);
        return;
    }
    if (route == RESET) {
        ankah_session_totals sessions;
        const char *persistence;
        char reply[112];
        int saved;
        uint64_t wall = (uint64_t)time(NULL);
        if (strcmp(c->request.method, "POST") != 0) {
            respond(c, 405, "Method Not Allowed", "text/plain", "Use POST\n", "Allow: POST\r\n");
            return;
        }
        ankah_stats_init(wall);
        body_release(config.live_body);
        config.live_body = NULL;
        stats_sample(wall, &sessions);
        saved = save_stats();
        persistence = saved > 0 ? "saved" : saved == 0 ? "disabled" : "failed";
        snprintf(reply, sizeof(reply),
                 "{\"epoch\":%" PRIu64 ",\"persistence\":\"%s\"}\n",
                 wall, persistence);
        respond(c, 200, "OK", "application/json", reply, NULL);
        return;
    }
    if (strcmp(c->request.method, "GET") != 0) {
        respond(c, 405, "Method Not Allowed", "text/plain", "Use GET\n", "Allow: GET\r\n");
        return;
    }
    if (route == EXPORT) {
        char extra[128], timestamp[32];
        uint64_t exported_at;
        time_t stamp;
        struct tm *utc;
        int length;
        body = render_export(&exported_at);
        stamp = (time_t)exported_at;
        utc = gmtime(&stamp);
        length = utc && strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%SZ", utc)
            ? snprintf(extra, sizeof(extra),
                       "Content-Disposition: attachment; "
                       "filename=\"ankah-metrics-%s.csv\"\r\n", timestamp)
            : -1;
        if (length < 0 || (size_t)length >= sizeof(extra)) {
            body_release(body);
            body = NULL;
        }
        if (!body) {
            respond(c, 503, "Unavailable", "text/plain", "Statistics unavailable\n", NULL);
            return;
        }
        send_body(c, body, "text/csv; charset=utf-8", extra);
        return;
    }
    if (route == METRICS) body = render_metrics();
    else if (route == SCHEMA) body = render_schema();
    else if (route == LIVE) body = live_body();
    else {
        uint64_t hours = ANKAH_STAT_HOURS, days = ANKAH_STAT_DAYS;
        if (history_query(query ? query + 1 : NULL, &hours, &days) != 0) {
            respond(c, 400, "Bad Request", "text/plain", "Invalid history range\n", NULL);
            return;
        }
        body = render_history(hours, days);
    }
    if (!body) {
        respond(c, 503, "Unavailable", "text/plain", "Statistics unavailable\n", NULL);
        return;
    }
    send_body(c, body, route == METRICS
        ? "text/plain; version=0.0.4; charset=utf-8" : "application/json", NULL);
}

typedef enum {
    ROUTE_HEALTH, ROUTE_CONTINUATION, ROUTE_INTERNAL, ROUTE_STATIC,
    ROUTE_DASHBOARD_API, ROUTE_CHALLENGE, ROUTE_DASHBOARD_REDIRECT,
    ROUTE_DASHBOARD_ASSET, ROUTE_SPA, ROUTE_UPSTREAM
} request_route;

static const char *dashboard_public_target(const char *target) {
    size_t length;
    if (!config.dashboard_public_route[0] ||
        !prefix(target, config.dashboard_public_route)) return NULL;
    length = strlen(config.dashboard_public_route);
    return target + length - 1;
}

static int dashboard_public_api(const connection *c) {
    const char *target = dashboard_public_target(c->request.target);
    size_t length;
    if (!target) return 0;
    length = strcspn(target, "?");
    return strncmp(target, "/stats/", 7) == 0 ||
           strncmp(target, "/auth/", 6) == 0 || same_path(target, length, "/metrics");
}

static int dashboard_public_bare_path(const connection *c) {
    size_t route_length, target_length;
    if (!config.dashboard_public_route[0]) return 0;
    route_length = strlen(config.dashboard_public_route);
    target_length = strcspn(c->request.target, "?");
    return target_length + 1 == route_length &&
           strncmp(c->request.target, config.dashboard_public_route, target_length) == 0;
}

static void serve_dashboard_public_redirect(connection *c) {
    char extra[ANKAH_MAX_TARGET + 64];
    const char *query = strchr(c->request.target, '?');
    int length = snprintf(extra, sizeof(extra), "Location: %s%s\r\n",
                          config.dashboard_public_route, query ? query : "");
    if (length < 0 || (size_t)length >= sizeof(extra)) { close_connection(c); return; }
    respond(c, 308, "Permanent Redirect", "text/plain", "Dashboard moved\n", extra);
}

static int continuation_route(const connection *c) {
    ankah_session *session;
    const char *type = ankah_header_value(&c->request, "Content-Type");
    if (strcmp(c->request.method, "POST") != 0) return 0;
    session = request_session(&c->request);
    return session && session->is_post &&
           strcmp(c->request.target, session->target) == 0 &&
           ankah_session_solved(session, (uint64_t)time(NULL)) &&
           type && prefix(type, "application/x-www-form-urlencoded") &&
           c->request.content_length == 47;
}

/* Decides where a request goes before its body is read, so the body limit
 * can depend on whether the body is forwarded. handle_initial dispatches on
 * the result, in this order. */
static request_route route_request(const connection *c) {
    if (health_route(c)) return ROUTE_HEALTH;
    if (continuation_route(c)) return ROUTE_CONTINUATION;
    if (dashboard_public_api(c)) return ROUTE_DASHBOARD_API;
    if (prefix(c->request.target, "/ankah/")) return ROUTE_INTERNAL;
    if (static_route(c)) return ROUTE_STATIC;
    if (!allowed(&c->request, c->proved, c->crawler)) return ROUTE_CHALLENGE;
    if (dashboard_public_bare_path(c)) return ROUTE_DASHBOARD_REDIRECT;
    if (dashboard_public_target(c->request.target)) return ROUTE_DASHBOARD_ASSET;
    if (spa_route(c)) return ROUTE_SPA;
    return ROUTE_UPSTREAM;
}

static size_t forward_body_limit(void) {
    return config.max_upload > MAX_BODY ? config.max_upload : MAX_BODY;
}

static uint64_t body_deadline_ns(const connection *c) {
    uint64_t earned = c->large_body ?
        (uint64_t)c->body_received / UPLOAD_MIN_RATE * UINT64_C(1000000000) : 0;
    return c->body_started_ns + UPLOAD_GRACE_NS + earned;
}

static void start_continuation(connection *c, size_t end) {
    c->capture_continue = 1;
    c->continue_expected = c->request.content_length;
    c->continue_received = c->body_received;
    memcpy(c->continue_body, c->initial + end, c->body_received);
    if (c->continue_received == c->continue_expected) finish_continue(c);
}

static void handle_initial(connection *c) {
    size_t end = header_end(c->initial, c->initial_size);
    size_t decoded = 0;
    const char *expect;
    int preadmitted;
    request_route route;
    if (!end) {
        if (c->initial_size >= ANKAH_HEADER_LIMIT) {
            c->headers_handled = 1;
            tally_client_bytes_in(c);
            respond(c, 431, "Request Header Fields Too Large", "text/plain",
                    "Request headers too large\n", NULL);
        }
        return;
    }
    c->headers_handled = 1;
    if (ankah_parse_request(c->initial, end, &c->request) != 0) {
        account_public_connection(c);
        tally(c, ANKAH_STAT_requests, 1);
        tally_client_bytes_in(c);
        respond(c, 400, "Bad Request", "text/plain", "Invalid HTTP request\n", NULL);
        return;
    }
    if (dashboard_public_api(c)) {
        c->dashboard_api = 1;
        registry_unlink(c);
    }
    if (!c->initial_accounted) {
        account_public_connection(c);
        tally(c, ANKAH_STAT_requests, 1);
        tally_client_bytes_in(c);
        c->initial_accounted = 1;
    }
    if (c->dashboard) {
        ankah_language_log_request(&c->request);
        handle_dashboard(c, end, c->request.target);
        return;
    }
    if (!c->internal && !c->initial_logged) {
        ankah_language_log_request(&c->request);
        c->initial_logged = 1;
    }
    if (prepare_client_ip(c) != 0) {
        if (c->internal && !language_already_logged(c))
            ankah_language_log_request(&c->request);
        respond(c, 400, "Bad Request", "text/plain", "Invalid forwarding information\n", NULL);
        return;
    }
    if (c->internal && !language_already_logged(c))
        ankah_language_log_request(&c->request);
    {
        const char *request_host = ankah_header_value(&c->request, "Host");
        if (!request_host || !same_ascii(request_host, config.public_host)) {
            respond(c, 421, "Misdirected Request", "text/plain",
                    "Unexpected Host\n", NULL);
            return;
        }
    }
    preadmitted = internal_admission(c, &c->proved);
    if (preadmitted < 0) {
        respond(c, 400, "Bad Request", "text/plain", "Invalid admission information\n", NULL);
        return;
    }
    if (!preadmitted) c->proved = c->crawler || request_proved(&c->request);
    if (!preadmitted) {
        int crawler_result = classify_crawler(c, 0);
        if (crawler_result) return;
    }
    c->rate_class = request_rate_class(&c->request, c->proved, c->crawler);
    if (c->admission_state == 0) {
        if (c->rate_class == RATE_ANONYMOUS &&
            config.anonymous_connections >= ANONYMOUS_CONNECTIONS) {
            tally(c, ANKAH_STAT_anonymous_connection_rejected, 1);
            respond(c, 503, "Service Unavailable", "text/plain",
                    "Anonymous connection capacity reached\n", "Retry-After: 1\r\n");
            return;
        }
        --config.pending_connections;
        c->admission_state = c->rate_class == RATE_ANONYMOUS ? 1 : 2;
        if (c->admission_state == 1) ++config.anonymous_connections;
    }
    if (!c->rate_checked) {
        int rate_result = 0;
        c->rate_checked = 1;
        if (!preadmitted)
            rate_result = allow_rate((rate_class)c->rate_class, c->peer_ip);
        if (rate_result) {
            if (rate_result == 1) abuse_event(c, ANKAH_ABUSE_CLIENT_RATE, NULL);
            tally(c, ANKAH_STAT_rate_limited, 1);
            tally(c, c->rate_class == RATE_PROTECTED ?
                  ANKAH_STAT_rate_limited_protected : ANKAH_STAT_rate_limited_anonymous, 1);
            respond(c, 429, "Too Many Requests", "text/plain",
                    "Rate limit exceeded\n", "Retry-After: 1\r\n");
            return;
        }
    }
    if (c->crawler && !c->crawler_slot && !c->external_crawler_slot_id) {
        if (ankah_crawler_acquire() != 0) {
            respond(c, 429, "Too Many Requests", "text/plain",
                    "Crawler concurrency exceeded\n", "Retry-After: 1\r\n");
            return;
        }
        c->crawler_slot = 1;
    }
    if (!admit_request(c)) return;
    expect = ankah_header_value(&c->request, "Expect");
    if (expect && (!same_ascii(expect, "100-continue") || !c->request.has_body)) {
        respond(c, 417, "Expectation Failed", "text/plain",
                "Unsupported expectation\n", NULL);
        return;
    }
    c->websocket = c->request.websocket;
    if (!c->request.chunked &&
        !c->websocket && c->initial_size - end > c->request.content_length) {
        respond(c, 413, "Content Too Large", "text/plain",
                "Unsupported request body\n", NULL);
        return;
    }
    route = route_request(c);
    if (route == ROUTE_DASHBOARD_API) c->dashboard_api = 1;
    if (route == ROUTE_CHALLENGE && c->trusted_direct_peer) {
        abuse_event(c, ANKAH_ABUSE_SCAN, c->request.target);
        /* Only a client address supplied by a trusted proxy may become a
         * DOTS filtering source, never the proxy itself. */
        if (ankah_dots_enabled() && strcmp(c->peer_ip, c->direct_peer_ip) != 0 &&
            !ankah_peer_is_trusted(c->peer_ip, config.trusted_proxies,
                                   config.trusted_proxy_count))
            ankah_dots_record(c->peer_ip, uv_hrtime());
    }
    if (c->request.chunked && route != ROUTE_UPSTREAM) {
        respond(c, 413, "Content Too Large", "text/plain",
                "Chunked request body is not supported for this route\n", NULL);
        return;
    }
    if (route == ROUTE_CHALLENGE &&
        (c->request.content_length > MAX_BODY ||
         (strcmp(c->request.method, "POST") == 0 &&
          c->request.content_length > ANKAH_POST_REPLAY_MAX))) {
        respond_unlock_required(c, 413, "Content Too Large",
                                "Unlock, then retry this upload.", NULL);
        return;
    }
    if (!c->request.chunked && c->request.content_length >
        (route == ROUTE_UPSTREAM ? forward_body_limit() : MAX_BODY)) {
        respond(c, 413, "Content Too Large", "text/plain",
                "Request body too large\n", NULL);
        return;
    }
    if (c->request.chunked) {
        int chunk_result;
        ankah_chunked_body_init(&c->chunked_body);
        chunk_result = ankah_chunked_body_consume(&c->chunked_body,
                        c->initial + end, c->initial_size - end,
                        forward_body_limit(), &decoded);
        if (chunk_result < 0) {
            respond(c, c->chunked_body.limit_exceeded ? 413 : 400,
                    c->chunked_body.limit_exceeded ? "Content Too Large" : "Bad Request",
                    "text/plain", c->chunked_body.limit_exceeded ?
                    "Request body too large\n" : "Invalid chunked request body\n", NULL);
            return;
        }
        c->body_received = decoded;
    } else c->body_received = c->initial_size - end;
    c->large_body = c->request.chunked ? c->body_received > MAX_BODY :
                    c->request.content_length > MAX_BODY;
    c->body_started_ns = uv_hrtime();
    c->request_deadline_ns = request_body_complete(c) ? 0 : body_deadline_ns(c);
    c->reply_deadline_ns = ankah_reply_deadline_ns(
        c->body_started_ns, c->large_body, request_body_complete(c),
        c->upstream_final_started);
    refresh_timeout(c);
    if (c->closed) return;
    switch (route) {
    case ROUTE_HEALTH:
        serve_health_if_matched(c);
        break;
    case ROUTE_CONTINUATION:
        start_continuation(c, end);
        break;
    case ROUTE_INTERNAL:
        handle_internal(c);
        break;
    case ROUTE_STATIC:
        serve_static_if_matched(c);
        break;
    case ROUTE_DASHBOARD_API:
        handle_dashboard(c, end, dashboard_public_target(c->request.target));
        break;
    case ROUTE_CHALLENGE:
        handle_challenge(c);
        break;
    case ROUTE_DASHBOARD_REDIRECT:
        serve_dashboard_public_redirect(c);
        break;
    case ROUTE_DASHBOARD_ASSET:
        handle_dashboard(c, end, dashboard_public_target(c->request.target));
        break;
    case ROUTE_SPA:
        serve_spa_fallback(c);
        break;
    case ROUTE_UPSTREAM:
        uv_read_stop((uv_stream_t *)&c->client);
        if (start_upstream(c) != 0)
            respond(c, 502, "Bad Gateway", "text/plain", "Upstream unavailable\n", NULL);
        break;
    }
}

static void on_client_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer) {
    connection *c = (connection *)stream->data;
    if (count > 0 && !c->closed) {
        c->bytes_in += (uint64_t)count;
        if (c->headers_handled) tally_client_bytes_in(c);
        refresh_timeout(c);
        if (c->closed) { free(buffer->base); return; }
        if (c->response_finishing) {
            /* The upstream has finished, so no more request data is forwarded. */
        } else if (c->capture_session) {
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
        } else if (!c->forwarding && c->headers_handled) {
            /* The request is already being answered locally. Drain any body
             * that follows so closing does not reset the reply. */
        } else if (!c->forwarding) {
            if ((size_t)count > ANKAH_HEADER_LIMIT - c->initial_size) {
                c->headers_handled = 1;
                respond(c, 431, "Request Header Fields Too Large", "text/plain",
                        "Request headers too large\n", NULL);
            } else {
                memcpy(c->initial + c->initial_size, buffer->base, (size_t)count);
                c->initial_size += (size_t)count;
                handle_initial(c);
            }
        } else {
            if (!c->websocket) {
                if (c->request.chunked) {
                    size_t decoded = 0;
                    if (ankah_chunked_body_consume(&c->chunked_body, buffer->base,
                            (size_t)count, forward_body_limit(), &decoded) < 0) {
                        if (c->chunked_body.limit_exceeded && !c->upstream_final_started) {
                            c->forwarding = 0;
                            respond(c, 413, "Content Too Large", "text/plain",
                                    "Request body too large\n", NULL);
                            finish_upstream_response(c);
                        } else if (c->chunked_body.limit_exceeded) {
                            c->forwarding = 0;
                            c->request_deadline_ns = 0;
                            uv_read_stop(stream);
                            refresh_timeout(c);
                        } else close_connection(c);
                        free(buffer->base);
                        return;
                    }
                    c->body_received += decoded;
                    if (c->body_received > MAX_BODY) c->large_body = 1;
                } else {
                    if ((size_t)count > c->request.content_length - c->body_received) {
                        close_connection(c);
                        free(buffer->base);
                        return;
                    }
                    c->body_received += (size_t)count;
                }
                if (c->large_body) {
                    c->request_deadline_ns = body_deadline_ns(c);
                    refresh_timeout(c);
                }
            }
            if (queue_bytes(c, (uv_stream_t *)&c->upstream, stream,
                            buffer->base, (size_t)count, 0) != 0) close_connection(c);
            if (!c->websocket && request_body_complete(c)) {
                c->request_deadline_ns = 0;
                c->reply_deadline_ns = ankah_reply_deadline_ns(
                    uv_hrtime(), c->large_body, 1, c->upstream_final_started);
                refresh_timeout(c);
                uv_read_stop(stream);
            }
        }
    } else if (count < 0) {
        if (c->response_finishing && count == UV_EOF) {
            c->client_read_eof = 1;
            uv_read_stop(stream);
            if (c->client_shutdown_done) close_connection(c);
        } else close_connection(c);
    }
    free(buffer->base);
}

/* Latency is time to the first response byte. The status class comes from the
 * first chunk's status line; a response whose line is split is not classed. */
static void note_upstream_response(connection *c, const char *data, size_t size) {
    uint64_t elapsed = (uv_hrtime() - c->upstream_started_ns) / 1000000;
    c->status_seen = 1;
    tally(c, ANKAH_STAT_upstream_responses, 1);
    tally(c, ANKAH_STAT_upstream_latency_ms_total, elapsed);
    if (!c->dashboard) ankah_stats_max(ANKAH_STAT_upstream_latency_peak_ms, elapsed);
    if (size >= 12 && memcmp(data, "HTTP/1.", 7) == 0 && data[8] == ' ' &&
        data[9] >= '1' && data[9] <= '5' && data[10] >= '0' && data[10] <= '9' &&
        data[11] >= '0' && data[11] <= '9')
        tally_status(c, (data[9] - '0') * 100 + (data[10] - '0') * 10 + (data[11] - '0'));
}

static void on_upstream_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer) {
    connection *c = (connection *)stream->data;
    if (c->response_finishing && !c->forwarding) {
        free(buffer->base);
        return;
    }
    if (count > 0 && !c->closed) {
        tally(c, ANKAH_STAT_upstream_bytes_in, (uint64_t)count);
        if (!c->status_seen) note_upstream_response(c, buffer->base, (size_t)count);
        if (!c->upstream_final_started &&
            llhttp_execute(&c->upstream_response_parser, buffer->base,
                           (size_t)count) != HPE_OK)
            upstream_final_start(c);
        refresh_timeout(c);
        if (c->closed) { free(buffer->base); return; }
        if (queue_bytes(c, (uv_stream_t *)&c->client, stream,
                        buffer->base, (size_t)count, 0) != 0) close_connection(c);
    } else if (count < 0) {
        if (c->status_seen) finish_upstream_response(c);
        else close_connection(c);
    }
    free(buffer->base);
}

static void on_discard_closed(uv_handle_t *handle) {
    free(handle);
}

static void accept_connection(uv_stream_t *server, int dashboard) {
    connection *c;
    struct sockaddr_storage address;
    int address_size = sizeof(address);
    unsigned int *active = dashboard ? &config.dashboard_connections : &config.connections;
    if (*active >= (dashboard ? MAX_DASHBOARD_CONNECTIONS : MAX_CONNECTIONS) ||
        (!dashboard && config.pending_connections >= PENDING_CONNECTIONS)) {
        uv_tcp_t *discard = (uv_tcp_t *)malloc(sizeof(*discard));
        if (!dashboard) ankah_stats_add(ANKAH_STAT_refused, 1);
        if (!dashboard && config.pending_connections >= PENDING_CONNECTIONS)
            ankah_stats_add(ANKAH_STAT_pending_connection_refused, 1);
        if (discard && uv_tcp_init(config.loop, discard) == 0) {
            uv_accept(server, (uv_stream_t *)discard);
            uv_close((uv_handle_t *)discard, on_discard_closed);
        } else free(discard);
        return;
    }
    c = (connection *)calloc(1, sizeof(*c));
    if (!c) return;
    c->asset_index = -1;
    c->dashboard = dashboard;
    c->admission_state = dashboard ? -1 : 0;
    c->internal = server == (uv_stream_t *)&config.internal_listener;
    if (uv_tcp_init(config.loop, &c->client) != 0) { free(c); return; }
    c->client.data = c;
    c->handles = 1;
    ++*active;
    if (!dashboard) ++config.pending_connections;
    if (uv_accept(server, (uv_stream_t *)&c->client) != 0) {
        close_connection(c);
        return;
    }
    all_link(c);
    c->accepted_ms = uv_now(config.loop);
    if (config.dashboard && !dashboard) {
        c->id = ++config.next_connection_id;
        registry_link(c);
    }
    if (uv_timer_init(config.loop, &c->timer) != 0) {
        close_connection(c);
        return;
    }
    c->timer_initialized = 1;
    c->timer.data = c;
    ++c->handles;
    c->request_deadline_ns = uv_hrtime() + (dashboard ?
        UINT64_C(30000000000) : UINT64_C(5000000000));
    if (uv_tcp_getpeername(&c->client, (struct sockaddr *)&address, &address_size) == 0 &&
        address.ss_family == AF_INET) {
        uv_ip4_name((const struct sockaddr_in *)&address, c->peer_ip, sizeof(c->peer_ip));
    } else if (address.ss_family == AF_INET6) {
        uv_ip6_name((const struct sockaddr_in6 *)&address, c->peer_ip, sizeof(c->peer_ip));
    } else strcpy(c->peer_ip, "0.0.0.0");
    refresh_timeout(c);
    if (uv_read_start((uv_stream_t *)&c->client, allocate_read, on_client_read) != 0)
        close_connection(c);
}

static void on_new_connection(uv_stream_t *server, int status) {
    if (status >= 0) accept_connection(server, 0);
}

static void on_dashboard_connection(uv_stream_t *server, int status) {
    if (status >= 0) accept_connection(server, 1);
}

/* Returns 1 after a durable save, 0 when persistence is disabled, and -1
 * after a nonfatal persistence failure. */
static int save_stats(void) {
    uint64_t wall;
    if (!config.stats_path[0]) return 0;
    wall = (uint64_t)time(NULL);
    ankah_stats_roll(wall);
    if (ankah_stats_save(config.stats_path, wall) != 0) {
        if (!config.stats_persistence_failed)
            fprintf(stderr, "Ankah statistics persistence unavailable: %s\n",
                    config.stats_path);
        config.stats_persistence_failed = 1;
        return -1;
    }
    if (config.stats_persistence_failed)
        fprintf(stderr, "Ankah statistics persistence recovered: %s\n",
                config.stats_path);
    config.stats_persistence_failed = 0;
    return 1;
}

static void on_stats_tick(uv_timer_t *timer) {
    ankah_session_totals sessions;
    uint64_t now = uv_hrtime();
    (void)timer;
    stats_sample((uint64_t)time(NULL), &sessions);
    if (config.stats_path[0] && now >= config.next_stats_save_ns) {
        (void)save_stats();
        config.next_stats_save_ns = now + STATS_SAVE_NS;
    }
}

static void close_handle(uv_handle_t *handle) {
    if (!uv_is_closing(handle)) uv_close(handle, NULL);
}

static void close_connections(int include_dashboard) {
    connection *c = config.all_first;
    while (c) {
        connection *next = c->all_next;
        if (include_dashboard || !c->dashboard) close_connection(c);
        c = next;
    }
}

#ifndef _WIN32
static void clear_throttle_queue(void) {
    unsigned int i;
    for (i = 0; i < MAX_THROTTLE_QUEUE; ++i) {
        throttle_queue_entry *item = &config.throttle_queue[i];
        if (!item->active) continue;
        if (item->client && item->client->queued) --item->client->queued;
        item->active = 0;
    }
    config.throttle_queue_count = 0;
}
#endif

static void finish_shutdown(void) {
    if (config.lifecycle == LIFECYCLE_STOPPING) return;
    config.lifecycle = LIFECYCLE_STOPPING;
    close_handle((uv_handle_t *)&config.listener);
    if (config.internal_listener_initialized)
        close_handle((uv_handle_t *)&config.internal_listener);
    if (config.dashboard_listener_initialized)
        close_handle((uv_handle_t *)&config.dashboard_listener);
    if (config.stats_timer_initialized)
        close_handle((uv_handle_t *)&config.stats_timer);
    if (config.throttle_timer_initialized)
        close_handle((uv_handle_t *)&config.throttle_timer);
    ankah_dots_close();
#ifndef _WIN32
    if (config.terminate_signal_initialized)
        close_handle((uv_handle_t *)&config.terminate_signal);
    if (config.interrupt_signal_initialized)
        close_handle((uv_handle_t *)&config.interrupt_signal);
#endif
    close_connections(1);
    if (config.tls_certificate[0]) {
        ankah_frontend_force_close();
        ankah_h3_force_close();
        ankah_frontend_shutdown();
        ankah_h3_shutdown();
    }
}

static void maybe_finish_drain(void) {
    if (config.lifecycle != LIFECYCLE_DRAINING || config.active_requests) return;
    if (config.tls_certificate[0] &&
        (!ankah_frontend_is_drained() || !ankah_h3_is_drained())) return;
    close_handle((uv_handle_t *)&config.listener);
    if (config.internal_listener_initialized)
        close_handle((uv_handle_t *)&config.internal_listener);
    close_connections(0);
    if (config.tls_certificate[0]) {
        ankah_frontend_force_close();
        ankah_h3_force_close();
    }
    ankah_dots_close();
    if (config.child_started && !config.child_exited) {
        config.lifecycle = LIFECYCLE_CHILD_STOPPING;
        fprintf(stderr, "Ankah drained; stopping child\n");
        if (uv_process_kill(&config.child, SIGTERM) == 0) return;
    }
    finish_shutdown();
}

static void on_frontend_drained(void *data) {
    (void)data;
    maybe_finish_drain();
}

#ifndef _WIN32
static void on_shutdown_signal(uv_signal_t *handle, int number) {
    (void)handle;
    if (config.lifecycle == LIFECYCLE_RUNNING) {
        config.intentional_shutdown = 1;
        config.lifecycle = LIFECYCLE_DRAINING;
        fprintf(stderr, "Ankah draining after signal %d\n", number);
        clear_throttle_queue();
        if (config.tls_certificate[0]) {
            ankah_frontend_begin_drain();
            ankah_h3_begin_drain();
        }
        maybe_finish_drain();
        return;
    }
    fprintf(stderr, "Ankah forcing shutdown after signal %d\n", number);
    config.intentional_shutdown = 1;
    if (config.child_started && !config.child_exited)
        (void)uv_process_kill(&config.child, SIGKILL);
    finish_shutdown();
}
#endif

static void on_child_exit(uv_process_t *process, int64_t status, int signal_number) {
    fprintf(stderr, "Ankah child exited: status=%" PRId64 " signal=%d\n",
            status, signal_number);
    if (signal_number > 0 && signal_number <= INT_MAX - 128)
        config.child_exit_code = 128 + signal_number;
    else if (status >= 0 && status <= INT_MAX)
        config.child_exit_code = (int)status;
    else
        config.child_exit_code = EXIT_FAILURE;
    config.child_exited = 1;
    uv_close((uv_handle_t *)process, NULL);
    finish_shutdown();
}

int main(int argc, char **argv) {
    struct sockaddr_storage address;
    uv_process_options_t child_options;
    ankah_frontend_options frontend_options;
    int child_index, result;
#ifndef _WIN32
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Ankah failed to ignore SIGPIPE\n");
        return 1;
    }
#endif
    config.abuse_policy = ankah_abuse_create();
    if (!config.abuse_policy) return 1;
    if (parse_options(argc, argv, &child_index) != 0) {
        fprintf(stderr, "usage: ankah [--config path] "
                        "--public-origin https://host --secret-file path "
                        "[--listen ip:port] [--upstream ip:port] "
                        "[--allow-prefix /path] [--max-upload-mb n] "
                        "[--static-bundle dir] [--static-cache-mb n] "
                        "[--static-throttle-prefix /path/] "
                        "[--static-throttle-global-connections n] "
                        "[--static-throttle-client-connections n] "
                        "[--static-throttle-global-mbps n] "
                        "[--static-throttle-client-mbps n] "
                        "[--ankah-healthz[=/path]] [--ankah-livez[=/path]] "
                        "[--ankah-readyz[=/path]] "
                        "[--tls-cert path --tls-key path] [--http3 on|off] "
                        "[--trusted-proxy cidr] "
                        "[--proxy-abuse-profile off|conservative|strict] "
                        "[--dashboard-listen ip:port] [--dashboard-public-route /path/] "
                        "[--dashboard-token-file path] "
                        "[--stats-file path | --no-stats-file] "
                        "[--log-unknown-languages path] "
                        "[--dots-server ip:port --dots-server-name name "
                        "--dots-ca-file path --dots-cert-file path --dots-key-file path "
                        "--dots-cuid id --dots-protected-network cidr "
                        "[--dots-protected-port n] [--dots-threshold n] "
                        "[--dots-window-seconds n] [--dots-block-seconds n] "
                        "[--dots-path /path]] "
                        "[-- child command]\n");
        return 2;
    }
    if (ankah_crawlers_init() != 0) {
        fprintf(stderr, "Ankah failed to initialize crawler ranges\n");
        return 1;
    }
    if (config.unknown_languages_path[0] &&
        ankah_language_log_open(config.unknown_languages_path) != 0) {
        fprintf(stderr, "Ankah could not open unknown-language log: %s\n",
                config.unknown_languages_path);
        return 1;
    }
    config.loop = uv_default_loop();
#ifndef _WIN32
    if (uv_signal_init(config.loop, &config.terminate_signal) != 0 ||
        uv_signal_start(&config.terminate_signal, on_shutdown_signal, SIGTERM) != 0) {
        fprintf(stderr, "Ankah failed to initialize shutdown signals\n");
        return 1;
    }
    config.terminate_signal_initialized = 1;
    if (uv_signal_init(config.loop, &config.interrupt_signal) != 0 ||
        uv_signal_start(&config.interrupt_signal, on_shutdown_signal, SIGINT) != 0) {
        fprintf(stderr, "Ankah failed to initialize shutdown signals\n");
        return 1;
    }
    config.interrupt_signal_initialized = 1;
#endif
    if (config.throttle_prefix_count &&
        (config.throttle_global_bytes_per_second ||
         config.throttle_client_bytes_per_second)) {
        if (uv_timer_init(config.loop, &config.throttle_timer) != 0 ||
            uv_timer_start(&config.throttle_timer, on_throttle_tick,
                           THROTTLE_TICK_MS, THROTTLE_TICK_MS) != 0) {
            fprintf(stderr, "Ankah failed to start static throttling\n");
            return 1;
        }
        config.throttle_timer_initialized = 1;
        uv_unref((uv_handle_t *)&config.throttle_timer);
    }
    if (config.tls_certificate[0]) {
        struct sockaddr_in internal_address;
        int address_size = sizeof(internal_address);
        unsigned char random_key[32];
        if (ankah_random(random_key, sizeof(random_key)) != 0) {
            fprintf(stderr, "Ankah failed to initialize internal routing\n");
            return 1;
        }
        hex_encode(random_key, sizeof(random_key), config.internal_key);
        if (uv_ip4_addr("127.0.0.1", 0, &internal_address) != 0 ||
            uv_tcp_init(config.loop, &config.internal_listener) != 0 ||
            uv_tcp_bind(&config.internal_listener,
                        (const struct sockaddr *)&internal_address, 0) != 0 ||
            uv_listen((uv_stream_t *)&config.internal_listener, 128,
                      on_new_connection) != 0 ||
            uv_tcp_getsockname(&config.internal_listener,
                               (struct sockaddr *)&internal_address, &address_size) != 0) {
            fprintf(stderr, "Ankah failed to initialize internal routing\n");
            return 1;
        }
        config.internal_listener_initialized = 1;
        memset(&frontend_options, 0, sizeof(frontend_options));
        frontend_options.loop = config.loop;
        frontend_options.certificate_path = config.tls_certificate;
        frontend_options.key_path = config.tls_key;
        frontend_options.internal_key = config.internal_key;
        frontend_options.internal_port = ntohs(internal_address.sin_port);
        frontend_options.http3_port = config.public_h3_port;
        frontend_options.admit = frontend_admit;
        frontend_options.drained = on_frontend_drained;
        if (ankah_frontend_init(&frontend_options) != 0) {
            fprintf(stderr, "Ankah failed to initialize TLS\n");
            return 1;
        }
    }
    if (socket_address(config.listen_ip, config.listen_port, &address) != 0) {
        fprintf(stderr, "Ankah failed to listen\n");
        return 1;
    }
    if (config.tls_certificate[0] && config.http3_enabled &&
        ankah_h3_init(&frontend_options, (const struct sockaddr *)&address) != 0) {
        fprintf(stderr, "Ankah failed to bind HTTP/3 UDP listener\n");
        return 1;
    }
    if (
        uv_tcp_init(config.loop, &config.listener) != 0 ||
        uv_tcp_bind(&config.listener, (const struct sockaddr *)&address, 0) != 0 ||
        uv_listen((uv_stream_t *)&config.listener, 128,
                  config.tls_certificate[0] ? ankah_frontend_accept : on_new_connection) != 0) {
        fprintf(stderr, "Ankah failed to listen\n");
        return 1;
    }
    if (config.dashboard) {
        uint64_t wall = (uint64_t)time(NULL);
        int restore = config.stats_path[0]
            ? ankah_stats_restore(config.stats_path, wall) : 0;
        if (!config.stats_path[0]) ankah_stats_init(wall);
        if (restore & ANKAH_STATS_DEGRADED) {
            fprintf(stderr, "Ankah statistics snapshot was unavailable or invalid: %s\n",
                    config.stats_path);
            config.stats_persistence_failed = 1;
        }
        config.next_stats_save_ns = uv_hrtime() + STATS_SAVE_NS;
        if (config.dashboard_ip[0]) {
            struct sockaddr_storage dashboard_address;
            if (socket_address(config.dashboard_ip, config.dashboard_port,
                               &dashboard_address) != 0 ||
                uv_tcp_init(config.loop, &config.dashboard_listener) != 0) {
                fprintf(stderr, "Ankah failed to listen for the dashboard\n");
                return 1;
            }
            config.dashboard_listener_initialized = 1;
            if (uv_tcp_bind(&config.dashboard_listener,
                            (const struct sockaddr *)&dashboard_address, 0) != 0 ||
                uv_listen((uv_stream_t *)&config.dashboard_listener, 16,
                          on_dashboard_connection) != 0) {
                fprintf(stderr, "Ankah failed to listen for the dashboard\n");
                return 1;
            }
            fprintf(stderr, "Ankah dashboard listening on %s:%d\n",
                    config.dashboard_ip, config.dashboard_port);
        }
        if (uv_timer_init(config.loop, &config.stats_timer) != 0) {
            fprintf(stderr, "Ankah failed to start statistics\n");
            return 1;
        }
        config.stats_timer_initialized = 1;
        if (uv_timer_start(&config.stats_timer, on_stats_tick, 60000, 60000) != 0) {
            fprintf(stderr, "Ankah failed to start statistics\n");
            return 1;
        }
        uv_unref((uv_handle_t *)&config.stats_timer);
    }
    if (config.dashboard_public_route[0])
        fprintf(stderr, "Ankah dashboard public route is %s\n", config.dashboard_public_route);
    if (ankah_dots_start(config.loop) != 0) {
        fprintf(stderr, "Ankah failed to start the DOTS client\n");
        return 1;
    }
    if (child_index < argc) {
        memset(&child_options, 0, sizeof(child_options));
        config.child_exit_code = EXIT_FAILURE;
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
    result = uv_run(config.loop, UV_RUN_DEFAULT) == 0 ? 0 : 1;
    if (config.intentional_shutdown) result = 0;
    else if (config.child_started) result = config.child_exit_code;
    if (config.dashboard) (void)save_stats();
    if (config.tls_certificate[0]) {
        ankah_frontend_shutdown();
        ankah_h3_shutdown();
    }
    ankah_language_log_close();
    ankah_abuse_destroy(config.abuse_policy);
    return result;
}
