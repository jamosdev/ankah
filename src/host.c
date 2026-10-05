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
const ankah_upstream_policy *ankah_host_policy_const(const ankah_host *host, unsigned int route) {
    unsigned int index = host->routes[route].policy_index;
    return index ? &host->policies[index - 1] : &host->defaults;
}
ankah_upstream_policy *ankah_host_policy(ankah_host *host, unsigned int route) {
    unsigned int index = host->routes[route].policy_index;
    return index ? &host->policies[index - 1] : &host->defaults;
}
static int route_path(const ankah_exact_route *route, const char *path, size_t size) {
    size_t length = strlen(route->path);
    return route->prefix ? size >= length && !memcmp(path, route->path, length) :
        size == length && !memcmp(path, route->path, length);
}
static int intersects(const char *left, const char *right) {
    size_t a = strlen(left), b = strlen(right);
    return !memcmp(left, right, a < b ? a : b);
}
int ankah_host_route_conflict(const ankah_host *host, unsigned int route) {
    const ankah_exact_route *r = &host->routes[route];
    size_t i;
    if (!r->prefix) return ankah_host_local_path(host, r->path);
    if (intersects(r->path, "/ankah/") ||
        (host->dashboard_route[0] && intersects(r->path, host->dashboard_route))) return 1;
    for (i = 0; i < host->bundle.count; ++i)
        if (route_path(r, host->bundle.entries[i].url, strlen(host->bundle.entries[i].url))) return 1;
    return 0;
}
static int unambiguous_prefix_path(const char *target, size_t size) {
    size_t i, start = 1;
    for (i = 0; i < size; ++i) {
        if (target[i] == '%' || target[i] == '\\' || target[i] == '#') return 0;
        if (target[i] == '/' && i && target[i - 1] == '/') return 0;
        if (i && target[i] == '/') {
            size_t n = i - start;
            if ((n == 1 && target[start] == '.') ||
                (n == 2 && target[start] == '.' && target[start + 1] == '.')) return 0;
            start = i + 1;
        }
    }
    return !((size - start == 1 && target[start] == '.') ||
             (size - start == 2 && target[start] == '.' && target[start + 1] == '.'));
}
int ankah_host_local_path(const ankah_host *host, const char *target) {
    char path[ANKAH_MAX_TARGET];
    size_t n = strcspn(target, "?"), dashboard = strlen(host->dashboard_route);
    if (n >= sizeof(path)) return 0;
    memcpy(path, target, n); path[n] = 0;
    if (!strncmp(path, "/ankah/", 7)) return 1;
    if (dashboard && (!strncmp(path, host->dashboard_route, dashboard) ||
        (n + 1 == dashboard && !memcmp(path, host->dashboard_route, n)))) return 1;
    return ankah_static_find(&host->bundle, path) != NULL;
}

int ankah_host_request(const ankah_host *host, const ankah_request *request,
                       const char *authority, int h2, unsigned int *route) {
    static const char *const sensitive[] = {
        "Host", "Authorization", "Idempotency-Key", "Content-Type",
        "Content-Length", "Transfer-Encoding", "Expect"
    };
    unsigned int seen[7] = {0}, i, j, port;
    char name[256];
    int best_exact = 0, query_allowed = 0;
    size_t path_size = strcspn(request->target, "?"), best_length = 0;
    const ankah_exact_route *best = NULL;
    *route = ANKAH_LOCAL_ROUTE;
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
    if (host->primary) return 0;
    /* Select path ownership before method/query checks. Never fall through to
     * a broader route when the most specific owner rejects the request. */
    for (i = 0; i < host->route_count; ++i) {
        const ankah_exact_route *r = &host->routes[i];
        size_t length = strlen(r->path);
        if (!route_path(r, request->target, path_size)) continue;
        if (!best || (!r->prefix && !best_exact) ||
            (!best_exact && r->prefix && length > best_length)) {
            best = r; best_length = length; best_exact = !r->prefix;
        }
    }
    if (!best) return ankah_host_local_path(host, request->target) ? 0 : 404;
    if (best->prefix && !unambiguous_prefix_path(request->target, path_size)) return 404;
    for (i = 0; i < host->route_count; ++i) {
        const ankah_exact_route *r = &host->routes[i];
        if (r->prefix != best->prefix || strcmp(r->path, best->path)) continue;
        if (path_size == strlen(request->target) || r->query) query_allowed = 1;
        if (!strcmp(request->method, r->method)) {
            if (path_size != strlen(request->target) && !r->query) return 404;
            *route = i;
            return request->content_length > ankah_host_policy_const(host, i)->body_limit ? 413 : 0;
        }
    }
    return query_allowed ? 405 : 404;
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
