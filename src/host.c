#include "ankah/host.h"
#include <string.h>
#include <stdlib.h>

static int equal(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char x = (unsigned char)*a++, y = (unsigned char)*b++;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
    }
    return *a == *b;
}
int ankah_authority(const char *text, unsigned int default_port,
                    char name[256], unsigned int *port) {
    size_t n = 0, label = 0;
    unsigned int value = 0;
    const char *at = text;
    if (!at || !*at) return -1;
    while (*at && *at != ':') {
        unsigned char c = (unsigned char)*at++;
        if (c >= 'A' && c <= 'Z') c += 32;
        if (n >= 253) return -1;
        if (c == '.') {
            if (!label || name[n - 1] == '-') return -1;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                return -1;
            if ((!label && c == '-') || ++label > 63) return -1;
        }
        name[n++] = (char)c;
    }
    if (!label || name[n - 1] == '-') return -1;
    name[n] = 0;
    *port = default_port;
    if (*at) {
        ++at;
        if (!*at || (*at == '0' && at[1])) return -1;
        while (*at) {
            if (*at < '0' || *at > '9') return -1;
            value = value * 10 + (unsigned int)(*at++ - '0');
            if (value > 65535) return -1;
        }
        if (!value) return -1;
        *port = value;
    }
    return 0;
}
int ankah_host_origin(ankah_host *host, const char *origin) {
    if (strncmp(origin, "https://", 8) || strlen(origin) >= sizeof(host->origin) ||
        ankah_authority(origin + 8, 443, host->name, &host->port)) return -1;
    strcpy(host->origin, origin);
    strcpy(host->authority, origin + 8);
    return 0;
}
int ankah_host_find(const ankah_host *hosts, unsigned int count, const char *authority) {
    char name[256];
    unsigned int port, i;
    if (ankah_authority(authority, 443, name, &port)) return -400;
    for (i = 0; i < count; ++i)
        if (!strcmp(name, hosts[i].name) && port == hosts[i].port) return (int)i;
    return -421;
}
static int nominated(const char *value, const char *name) {
    while (*value) {
        char token[ANKAH_MAX_FIELD];
        size_t n = 0;
        while (*value == ' ' || *value == '\t' || *value == ',') ++value;
        while (*value && *value != ',' && n + 1 < sizeof(token)) token[n++] = *value++;
        while (n && (token[n - 1] == ' ' || token[n - 1] == '\t')) --n;
        token[n] = 0;
        if (equal(token, name)) return 1;
        while (*value && *value != ',') ++value;
    }
    return 0;
}
int ankah_host_request(const ankah_host *host, const ankah_request *request,
                       const char *authority, int h2, unsigned int *route) {
    static const char *const sensitive[] = {
        "Host", "Authorization", "Idempotency-Key", "Content-Type",
        "Content-Length", "Transfer-Encoding", "Expect"
    };
    unsigned int seen[7] = {0}, i, j, port;
    char name[256];
    int path_found = 0;
    if (ankah_authority(authority, 443, name, &port)) return 400;
    if (strcmp(name, host->name) || port != host->port) return 421;
    for (i = 0; i < request->count; ++i) {
        const ankah_header *header = &request->headers[i];
        for (j = 0; j < 7; ++j) {
            if (equal(header->name, sensitive[j]) && ++seen[j] > 1) return 400;
            if (equal(header->name, "Connection") && nominated(header->value, sensitive[j]))
                return 400;
        }
        if (equal(header->name, "Host")) {
            if (ankah_authority(header->value, 443, name, &port)) return 400;
            if (strcmp(name, host->name) || port != host->port) return 421;
        }
        if (h2 && (equal(header->name, "Connection") ||
                   equal(header->name, "Transfer-Encoding") ||
                   equal(header->name, "Upgrade") || equal(header->name, "Keep-Alive") ||
                   equal(header->name, "Proxy-Connection"))) return 400;
        if (host->route_count && (equal(header->name, "Trailer") ||
                                  equal(header->name, "Upgrade"))) return 400;
    }
    if (!h2 && seen[0] != 1) return 400;
    if (!host->route_count) return 0;
    for (i = 0; i < host->route_count; ++i) {
        if (strcmp(request->target, host->routes[i].path)) continue;
        path_found = 1;
        if (!strcmp(request->method, host->routes[i].method)) {
            *route = i;
            return request->content_length > host->body_limit ? 413 : 0;
        }
    }
    return path_found ? 405 : 404;
}

static size_t queue_limit[2], queue_used[2], queue_high[2];
void ankah_queue_limits(size_t request_limit, size_t response_limit) {
    queue_limit[0] = request_limit; queue_limit[1] = response_limit;
}
int ankah_queue_reserve(int response, size_t bytes) {
    unsigned int i = response ? 1U : 0U;
    if (bytes > (size_t)-1 - queue_used[i] ||
        (queue_limit[i] && (queue_used[i] > queue_limit[i] ||
         bytes > queue_limit[i] - queue_used[i]))) return -1;
    queue_used[i] += bytes;
    if (queue_used[i] > queue_high[i]) queue_high[i] = queue_used[i];
    return 0;
}
void ankah_queue_release(int response, size_t bytes) {
    unsigned int i = response ? 1U : 0U;
    queue_used[i] -= bytes;
}
size_t ankah_queue_current(int response) { return queue_used[response ? 1 : 0]; }
size_t ankah_queue_peak(int response) { return queue_high[response ? 1 : 0]; }

uint64_t ankah_absolute_timeout_ms(uint64_t now, uint64_t first,
                                  uint64_t second, uint64_t third) {
    uint64_t deadline = first;
    if (second && (!deadline || second < deadline)) deadline = second;
    if (third && (!deadline || third < deadline)) deadline = third;
    if (!deadline || deadline <= now) return 0;
    return (deadline - now) / 1000000 + ((deadline - now) % 1000000 != 0);
}
