#include "crawler.h"

#include "ankah/proxy.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define GOOGLE_RANGES 317
#define BING_CACHE_ENTRIES 128
#define BING_CACHE_TTL_NS UINT64_C(300000000000)
#define BING_HOST_MAX 1025

typedef struct {
    char ip[64];
    uint64_t checked_ns;
    int known;
} bing_cache_entry;

/* Google common crawler feed, retrieved 2026-09-22:
 * https://developers.google.com/crawling/ipranges/common-crawlers.json */
static const char *const google_range_text[GOOGLE_RANGES] = {
    "2001:4860:4801:10::/64",
    "2001:4860:4801:11::/64",
    "2001:4860:4801:12::/64",
    "2001:4860:4801:13::/64",
    "2001:4860:4801:14::/64",
    "2001:4860:4801:15::/64",
    "2001:4860:4801:16::/64",
    "2001:4860:4801:17::/64",
    "2001:4860:4801:18::/64",
    "2001:4860:4801:19::/64",
    "2001:4860:4801:1a::/64",
    "2001:4860:4801:1b::/64",
    "2001:4860:4801:1c::/64",
    "2001:4860:4801:1d::/64",
    "2001:4860:4801:1e::/64",
    "2001:4860:4801:1f::/64",
    "2001:4860:4801:20::/64",
    "2001:4860:4801:21::/64",
    "2001:4860:4801:22::/64",
    "2001:4860:4801:23::/64",
    "2001:4860:4801:24::/64",
    "2001:4860:4801:25::/64",
    "2001:4860:4801:26::/64",
    "2001:4860:4801:27::/64",
    "2001:4860:4801:28::/64",
    "2001:4860:4801:29::/64",
    "2001:4860:4801:2::/64",
    "2001:4860:4801:2a::/64",
    "2001:4860:4801:2b::/64",
    "2001:4860:4801:2c::/64",
    "2001:4860:4801:2d::/64",
    "2001:4860:4801:2e::/64",
    "2001:4860:4801:2f::/64",
    "2001:4860:4801:30::/64",
    "2001:4860:4801:31::/64",
    "2001:4860:4801:32::/64",
    "2001:4860:4801:33::/64",
    "2001:4860:4801:34::/64",
    "2001:4860:4801:35::/64",
    "2001:4860:4801:36::/64",
    "2001:4860:4801:37::/64",
    "2001:4860:4801:38::/64",
    "2001:4860:4801:39::/64",
    "2001:4860:4801:3a::/64",
    "2001:4860:4801:3b::/64",
    "2001:4860:4801:3c::/64",
    "2001:4860:4801:3d::/64",
    "2001:4860:4801:3e::/64",
    "2001:4860:4801:3f::/64",
    "2001:4860:4801:40::/64",
    "2001:4860:4801:41::/64",
    "2001:4860:4801:42::/64",
    "2001:4860:4801:43::/64",
    "2001:4860:4801:44::/64",
    "2001:4860:4801:45::/64",
    "2001:4860:4801:46::/64",
    "2001:4860:4801:47::/64",
    "2001:4860:4801:48::/64",
    "2001:4860:4801:49::/64",
    "2001:4860:4801:4a::/64",
    "2001:4860:4801:4b::/64",
    "2001:4860:4801:4c::/64",
    "2001:4860:4801:4d::/64",
    "2001:4860:4801:4e::/64",
    "2001:4860:4801:50::/64",
    "2001:4860:4801:51::/64",
    "2001:4860:4801:52::/64",
    "2001:4860:4801:53::/64",
    "2001:4860:4801:54::/64",
    "2001:4860:4801:55::/64",
    "2001:4860:4801:56::/64",
    "2001:4860:4801:57::/64",
    "2001:4860:4801:58::/64",
    "2001:4860:4801:59::/64",
    "2001:4860:4801:60::/64",
    "2001:4860:4801:61::/64",
    "2001:4860:4801:62::/64",
    "2001:4860:4801:63::/64",
    "2001:4860:4801:64::/64",
    "2001:4860:4801:65::/64",
    "2001:4860:4801:66::/64",
    "2001:4860:4801:67::/64",
    "2001:4860:4801:68::/64",
    "2001:4860:4801:69::/64",
    "2001:4860:4801:6a::/64",
    "2001:4860:4801:6b::/64",
    "2001:4860:4801:6c::/64",
    "2001:4860:4801:6d::/64",
    "2001:4860:4801:6e::/64",
    "2001:4860:4801:6f::/64",
    "2001:4860:4801:70::/64",
    "2001:4860:4801:71::/64",
    "2001:4860:4801:72::/64",
    "2001:4860:4801:73::/64",
    "2001:4860:4801:74::/64",
    "2001:4860:4801:75::/64",
    "2001:4860:4801:76::/64",
    "2001:4860:4801:77::/64",
    "2001:4860:4801:78::/64",
    "2001:4860:4801:79::/64",
    "2001:4860:4801:7a::/64",
    "2001:4860:4801:7b::/64",
    "2001:4860:4801:7c::/64",
    "2001:4860:4801:7d::/64",
    "2001:4860:4801:7e::/64",
    "2001:4860:4801:7f::/64",
    "2001:4860:4801:80::/64",
    "2001:4860:4801:81::/64",
    "2001:4860:4801:82::/64",
    "2001:4860:4801:83::/64",
    "2001:4860:4801:84::/64",
    "2001:4860:4801:85::/64",
    "2001:4860:4801:86::/64",
    "2001:4860:4801:87::/64",
    "2001:4860:4801:88::/64",
    "2001:4860:4801:90::/64",
    "2001:4860:4801:91::/64",
    "2001:4860:4801:92::/64",
    "2001:4860:4801:93::/64",
    "2001:4860:4801:94::/64",
    "2001:4860:4801:95::/64",
    "2001:4860:4801:96::/64",
    "2001:4860:4801:97::/64",
    "2001:4860:4801:a0::/64",
    "2001:4860:4801:a1::/64",
    "2001:4860:4801:a2::/64",
    "2001:4860:4801:a3::/64",
    "2001:4860:4801:a4::/64",
    "2001:4860:4801:a5::/64",
    "2001:4860:4801:a6::/64",
    "2001:4860:4801:a7::/64",
    "2001:4860:4801:a8::/64",
    "2001:4860:4801:a9::/64",
    "2001:4860:4801:aa::/64",
    "2001:4860:4801:ab::/64",
    "2001:4860:4801:ac::/64",
    "2001:4860:4801:ad::/64",
    "2001:4860:4801:ae::/64",
    "2001:4860:4801:b0::/64",
    "2001:4860:4801:b1::/64",
    "2001:4860:4801:b2::/64",
    "2001:4860:4801:b3::/64",
    "2001:4860:4801:b4::/64",
    "2001:4860:4801:b5::/64",
    "2001:4860:4801:b6::/64",
    "2001:4860:4801:c::/64",
    "2001:4860:4801:f::/64",
    "192.178.4.0/27",
    "192.178.4.128/27",
    "192.178.4.160/27",
    "192.178.4.192/27",
    "192.178.4.224/27",
    "192.178.4.32/27",
    "192.178.4.64/27",
    "192.178.4.96/27",
    "192.178.5.0/27",
    "192.178.6.0/27",
    "192.178.6.128/27",
    "192.178.6.160/27",
    "192.178.6.192/27",
    "192.178.6.224/27",
    "192.178.6.32/27",
    "192.178.6.64/27",
    "192.178.6.96/27",
    "192.178.7.0/27",
    "192.178.7.128/27",
    "192.178.7.160/27",
    "192.178.7.192/27",
    "192.178.7.224/27",
    "192.178.7.32/27",
    "192.178.7.64/27",
    "192.178.7.96/27",
    "34.100.182.96/28",
    "34.101.50.144/28",
    "34.118.254.0/28",
    "34.118.66.0/28",
    "34.126.178.96/28",
    "34.146.150.144/28",
    "34.147.110.144/28",
    "34.151.74.144/28",
    "34.152.50.64/28",
    "34.154.114.144/28",
    "34.155.98.32/28",
    "34.165.18.176/28",
    "34.175.160.64/28",
    "34.176.130.16/28",
    "34.22.85.0/27",
    "34.64.82.64/28",
    "34.65.242.112/28",
    "34.80.50.80/28",
    "34.88.194.0/28",
    "34.89.10.80/28",
    "34.89.198.80/28",
    "34.96.162.48/28",
    "35.247.243.240/28",
    "66.249.64.0/27",
    "66.249.64.128/27",
    "66.249.64.160/27",
    "66.249.64.192/27",
    "66.249.64.224/27",
    "66.249.64.32/27",
    "66.249.64.64/27",
    "66.249.64.96/27",
    "66.249.65.0/27",
    "66.249.65.128/27",
    "66.249.65.160/27",
    "66.249.65.192/27",
    "66.249.65.224/27",
    "66.249.65.32/27",
    "66.249.65.64/27",
    "66.249.65.96/27",
    "66.249.66.0/27",
    "66.249.66.128/27",
    "66.249.66.160/27",
    "66.249.66.192/27",
    "66.249.66.224/27",
    "66.249.66.32/27",
    "66.249.66.64/27",
    "66.249.66.96/27",
    "66.249.67.0/27",
    "66.249.67.32/27",
    "66.249.67.64/27",
    "66.249.68.0/27",
    "66.249.68.128/27",
    "66.249.68.160/27",
    "66.249.68.192/27",
    "66.249.68.224/27",
    "66.249.68.32/27",
    "66.249.68.64/27",
    "66.249.68.96/27",
    "66.249.69.0/27",
    "66.249.69.128/27",
    "66.249.69.160/27",
    "66.249.69.192/27",
    "66.249.69.224/27",
    "66.249.69.32/27",
    "66.249.69.64/27",
    "66.249.69.96/27",
    "66.249.70.0/27",
    "66.249.70.128/27",
    "66.249.70.160/27",
    "66.249.70.192/27",
    "66.249.70.224/27",
    "66.249.70.32/27",
    "66.249.70.64/27",
    "66.249.70.96/27",
    "66.249.71.0/27",
    "66.249.71.128/27",
    "66.249.71.160/27",
    "66.249.71.192/27",
    "66.249.71.224/27",
    "66.249.71.32/27",
    "66.249.71.64/27",
    "66.249.71.96/27",
    "66.249.72.0/27",
    "66.249.72.128/27",
    "66.249.72.160/27",
    "66.249.72.192/27",
    "66.249.72.224/27",
    "66.249.72.32/27",
    "66.249.72.64/27",
    "66.249.72.96/27",
    "66.249.73.0/27",
    "66.249.73.128/27",
    "66.249.73.160/27",
    "66.249.73.192/27",
    "66.249.73.224/27",
    "66.249.73.32/27",
    "66.249.73.64/27",
    "66.249.73.96/27",
    "66.249.74.0/27",
    "66.249.74.128/27",
    "66.249.74.160/27",
    "66.249.74.192/27",
    "66.249.74.224/27",
    "66.249.74.32/27",
    "66.249.74.64/27",
    "66.249.74.96/27",
    "66.249.75.0/27",
    "66.249.75.128/27",
    "66.249.75.160/27",
    "66.249.75.192/27",
    "66.249.75.224/27",
    "66.249.75.32/27",
    "66.249.75.64/27",
    "66.249.75.96/27",
    "66.249.76.0/27",
    "66.249.76.128/27",
    "66.249.76.160/27",
    "66.249.76.192/27",
    "66.249.76.224/27",
    "66.249.76.32/27",
    "66.249.76.64/27",
    "66.249.76.96/27",
    "66.249.77.0/27",
    "66.249.77.128/27",
    "66.249.77.160/27",
    "66.249.77.192/27",
    "66.249.77.224/27",
    "66.249.77.32/27",
    "66.249.77.64/27",
    "66.249.77.96/27",
    "66.249.78.0/27",
    "66.249.78.128/27",
    "66.249.78.160/27",
    "66.249.78.192/27",
    "66.249.78.224/27",
    "66.249.78.32/27",
    "66.249.78.64/27",
    "66.249.78.96/27",
    "66.249.79.0/27",
    "66.249.79.128/27",
    "66.249.79.160/27",
    "66.249.79.192/27",
    "66.249.79.224/27",
    "66.249.79.32/27",
    "66.249.79.64/27",
};
static ankah_network google_ranges[GOOGLE_RANGES];
static bing_cache_entry bing_cache[BING_CACHE_ENTRIES];
static unsigned int crawler_active;

typedef struct {
    uv_getnameinfo_t reverse;
    uv_getaddrinfo_t forward;
    ankah_bingbot_callback callback;
    void *data;
    char ip[64];
    char host[BING_HOST_MAX];
} bing_lookup;

static bing_lookup *active_lookup;

static int domain_suffix(const char *name, const char *suffix) {
    size_t name_size = strlen(name), suffix_size = strlen(suffix);
    return name_size > suffix_size &&
           strcmp(name + name_size - suffix_size, suffix) == 0;
}

static void lowercase(char *text) {
    while (*text) {
        if (*text >= 'A' && *text <= 'Z') *text = (char)(*text + 'a' - 'A');
        ++text;
    }
}

static int forward_matches(const struct addrinfo *answers, const char *ip) {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    const struct addrinfo *item;
    if (strchr(ip, ':')) {
        memset(&v6, 0, sizeof(v6));
        if (uv_inet_pton(AF_INET6, ip, &v6.sin6_addr) != 0) return 0;
        for (item = answers; item; item = item->ai_next)
            if (item->ai_family == AF_INET6 &&
                memcmp(&v6.sin6_addr, &((const struct sockaddr_in6 *)item->ai_addr)->sin6_addr,
                       sizeof(v6.sin6_addr)) == 0) return 1;
    } else {
        memset(&v4, 0, sizeof(v4));
        if (uv_inet_pton(AF_INET, ip, &v4.sin_addr) != 0) return 0;
        for (item = answers; item; item = item->ai_next)
            if (item->ai_family == AF_INET &&
                memcmp(&v4.sin_addr, &((const struct sockaddr_in *)item->ai_addr)->sin_addr,
                       sizeof(v4.sin_addr)) == 0) return 1;
    }
    return 0;
}

static void cache_result(const char *ip, int known) {
    bing_cache_entry *entry = &bing_cache[0];
    unsigned int i;
    for (i = 0; i < BING_CACHE_ENTRIES; ++i) {
        if (strcmp(bing_cache[i].ip, ip) == 0) { entry = &bing_cache[i]; break; }
        if (bing_cache[i].checked_ns < entry->checked_ns) entry = &bing_cache[i];
    }
    strcpy(entry->ip, ip);
    entry->checked_ns = uv_hrtime();
    entry->known = known;
}

static void finish_lookup(bing_lookup *lookup, int verified) {
    ankah_bingbot_callback callback = lookup->callback;
    void *data = lookup->data;
    cache_result(lookup->ip, verified);
    active_lookup = NULL;
    free(lookup);
    if (callback) callback(data, verified);
}

static void on_forward(uv_getaddrinfo_t *request, int status,
                       struct addrinfo *answers) {
    bing_lookup *lookup = request->data;
    int verified = status == 0 && answers && forward_matches(answers, lookup->ip);
    if (answers) uv_freeaddrinfo(answers);
    finish_lookup(lookup, verified);
}

static void on_reverse(uv_getnameinfo_t *request, int status,
                       const char *hostname, const char *service) {
    bing_lookup *lookup = request->data;
    struct addrinfo hints;
    int result;
    (void)service;
    if (status != 0 || !hostname || strlen(hostname) >= sizeof(lookup->host)) {
        finish_lookup(lookup, 0);
        return;
    }
    strcpy(lookup->host, hostname);
    lowercase(lookup->host);
    if (!domain_suffix(lookup->host, ".search.msn.com") &&
        !domain_suffix(lookup->host, ".bing.com")) {
        finish_lookup(lookup, 0);
        return;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = strchr(lookup->ip, ':') ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    lookup->forward.data = lookup;
    result = uv_getaddrinfo(request->loop, &lookup->forward, on_forward,
                            lookup->host, NULL, &hints);
    if (result != 0) finish_lookup(lookup, 0);
}

static int bingbot_address(const char *ip, struct sockaddr_storage *out) {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    memset(out, 0, sizeof(*out));
    if (strchr(ip, ':')) {
        memset(&v6, 0, sizeof(v6));
        v6.sin6_family = AF_INET6;
        if (uv_inet_pton(AF_INET6, ip, &v6.sin6_addr) != 0) return -1;
        memcpy(out, &v6, sizeof(v6));
    } else {
        memset(&v4, 0, sizeof(v4));
        v4.sin_family = AF_INET;
        if (uv_inet_pton(AF_INET, ip, &v4.sin_addr) != 0) return -1;
        memcpy(out, &v4, sizeof(v4));
    }
    return 0;
}

int ankah_bingbot_cache_lookup(const char *ip, int *verified) {
    uint64_t now = uv_hrtime();
    unsigned int i;
    for (i = 0; i < BING_CACHE_ENTRIES; ++i) {
        if (strcmp(bing_cache[i].ip, ip) == 0 &&
            now - bing_cache[i].checked_ns < BING_CACHE_TTL_NS) {
            *verified = bing_cache[i].known;
            return 1;
        }
    }
    return 0;
}

int ankah_crawlers_init(void) {
    unsigned int i;
    for (i = 0; i < GOOGLE_RANGES; ++i)
        if (ankah_parse_network(google_range_text[i], &google_ranges[i]) != 0) return -1;
    return 0;
}

int ankah_google_crawler_is_known(const char *ip) {
    return ankah_peer_is_trusted(ip, google_ranges, GOOGLE_RANGES);
}

int ankah_crawler_acquire(void) {
    if (crawler_active) return -1;
    crawler_active = 1;
    return 0;
}

void ankah_crawler_release(void) {
    crawler_active = 0;
}

int ankah_bingbot_verify_start(uv_loop_t *loop, const char *ip,
                               ankah_bingbot_callback callback, void *data) {
    bing_lookup *lookup;
    struct sockaddr_storage address;
    int result;
    if (!loop || active_lookup || bingbot_address(ip, &address) != 0) return -1;
    lookup = calloc(1, sizeof(*lookup));
    if (!lookup) return -1;
    strcpy(lookup->ip, ip);
    lookup->callback = callback;
    lookup->data = data;
    lookup->reverse.data = lookup;
    active_lookup = lookup;
    result = uv_getnameinfo(loop, &lookup->reverse, on_reverse,
                            (const struct sockaddr *)&address, NI_NAMEREQD);
    if (result != 0) { active_lookup = NULL; free(lookup); return -1; }
    return 0;
}

void ankah_bingbot_verify_cancel(void *data) {
    if (!active_lookup || active_lookup->data != data) return;
    active_lookup->callback = NULL;
    active_lookup->data = NULL;
    (void)uv_cancel((uv_req_t *)&active_lookup->reverse);
    (void)uv_cancel((uv_req_t *)&active_lookup->forward);
}
