#include "dots_policy.h"
#include <stdio.h>
#include <string.h>

int ankah_dots_tracker_hit(ankah_dots_tracker *tracker, const char *ip,
                           uint64_t now_ns, unsigned int threshold, uint64_t window_ns) {
    ankah_dots_tracked *entry = NULL, *oldest;
    unsigned int i, kept = 0;
    if (!tracker || !ip || !*ip || strlen(ip) >= sizeof(tracker->entries[0].ip) ||
        threshold == 0 || threshold > ANKAH_DOTS_MAX_THRESHOLD) return 0;
    oldest = &tracker->entries[0];
    for (i = 0; i < ANKAH_DOTS_TRACKED; ++i) {
        ankah_dots_tracked *candidate = &tracker->entries[i];
        if (strcmp(candidate->ip, ip) == 0) { entry = candidate; break; }
        if (!candidate->ip[0]) { if (oldest->ip[0]) oldest = candidate; }
        else if (oldest->ip[0] && candidate->seen_ns < oldest->seen_ns) oldest = candidate;
    }
    if (!entry) {
        entry = oldest;
        memset(entry, 0, sizeof(*entry));
        strcpy(entry->ip, ip);
    }
    entry->seen_ns = now_ns;
    for (i = 0; i < entry->count; ++i) {
        uint64_t then = entry->times[i];
        if (now_ns >= then && now_ns - then < window_ns) entry->times[kept++] = then;
    }
    if (kept == ANKAH_DOTS_MAX_THRESHOLD) {
        memmove(entry->times, entry->times + 1, (kept - 1) * sizeof(entry->times[0]));
        --kept;
    }
    entry->times[kept++] = now_ns;
    entry->count = kept;
    if (kept < threshold) return 0;
    entry->count = 0;
    return 1;
}

int ankah_dots_acl_name(const char *ip, char *out, size_t capacity) {
    size_t i, length = strlen(ip);
    if (length == 0 || length + 7 > capacity) return -1;
    memcpy(out, "ankah-", 6);
    for (i = 0; i < length; ++i) {
        char ch = ip[i];
        if (ch == '.' || ch == ':') ch = '-';
        else if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                   (ch >= 'A' && ch <= 'F'))) return -1;
        out[6 + i] = ch;
    }
    out[6 + length] = 0;
    return 0;
}

static int address_text(const char *text) {
    size_t i;
    if (!*text) return 0;
    for (i = 0; text[i]; ++i) {
        char ch = text[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
              (ch >= 'A' && ch <= 'F') || ch == '.' || ch == ':' || ch == '/')) return 0;
    }
    return 1;
}

int ankah_dots_acl_body(const char *name, const char *ip, const char *destination,
                        unsigned int port, char *out, size_t capacity) {
    int v6 = strchr(ip, ':') != NULL;
    const char *slash = strchr(destination, '/');
    int written;
    if (!address_text(ip) || strchr(ip, '/') || !slash || !address_text(destination) ||
        (memchr(destination, ':', (size_t)(slash - destination)) != NULL) != v6 ||
        port == 0 || port > 65535 || !ankah_dots_valid_cuid(name)) return -1;
    written = snprintf(out, capacity,
        "{\"ietf-dots-data-channel:acls\":{\"acl\":[{"
        "\"name\":\"%s\","
        "\"type\":\"%s\","
        "\"activation-type\":\"immediate\","
        "\"aces\":{\"ace\":[{"
        "\"name\":\"block\","
        "\"matches\":{"
        "\"%s\":{\"source-%s-network\":\"%s/%s\",\"destination-%s-network\":\"%s\",\"protocol\":6},"
        "\"tcp\":{\"destination-port-range-or-operator\":{\"operator\":\"eq\",\"port\":%u}}"
        "},"
        "\"actions\":{\"forwarding\":\"drop\"}"
        "}]}}]}}",
        name, v6 ? "ipv6-acl-type" : "ipv4-acl-type",
        v6 ? "ipv6" : "ipv4", v6 ? "ipv6" : "ipv4", ip, v6 ? "128" : "32",
        v6 ? "ipv6" : "ipv4", destination, port);
    if (written < 0 || (size_t)written >= capacity) return -1;
    return written;
}

int ankah_dots_valid_cuid(const char *cuid) {
    size_t i, length = strlen(cuid);
    if (length == 0 || length >= 64) return 0;
    for (i = 0; i < length; ++i) {
        char ch = cuid[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') || ch == '-' || ch == '_')) return 0;
    }
    return 1;
}

int ankah_dots_client_body(const char *cuid, char *out, size_t capacity) {
    int written;
    if (!ankah_dots_valid_cuid(cuid)) return -1;
    written = snprintf(out, capacity,
                       "{\"ietf-dots-data-channel:dots-client\":[{\"cuid\":\"%s\"}]}", cuid);
    if (written < 0 || (size_t)written >= capacity) return -1;
    return written;
}

int ankah_dots_status(const char *response, size_t size) {
    int status = 0;
    size_t i;
    if (size < 12 || memcmp(response, "HTTP/1.", 7) != 0 || response[8] != ' ') return -1;
    for (i = 9; i < 12; ++i) {
        if (response[i] < '0' || response[i] > '9') return -1;
        status = status * 10 + (response[i] - '0');
    }
    if (size > 12 && response[12] != ' ' && response[12] != '\r') return -1;
    return status;
}

static size_t skip_space(const char *body, size_t at, size_t size) {
    while (at < size && (body[at] == ' ' || body[at] == '\t' ||
                         body[at] == '\r' || body[at] == '\n')) ++at;
    return at;
}

size_t ankah_dots_scan_names(const char *body, size_t size, const char *prefix,
                             char names[][ANKAH_DOTS_NAME_MAX], size_t max) {
    static const char key[] = "\"name\"";
    size_t found = 0, at = 0, prefix_size = strlen(prefix);
    while (found < max && at + sizeof(key) - 1 <= size) {
        size_t start, end;
        if (memcmp(body + at, key, sizeof(key) - 1) != 0) { ++at; continue; }
        at = skip_space(body, at + sizeof(key) - 1, size);
        if (at >= size || body[at] != ':') continue;
        at = skip_space(body, at + 1, size);
        if (at >= size || body[at] != '"') continue;
        start = ++at;
        while (at < size && body[at] != '"' && body[at] != '\\') ++at;
        if (at >= size || body[at] != '"') continue;
        end = at++;
        if (end - start < prefix_size || end - start >= ANKAH_DOTS_NAME_MAX ||
            memcmp(body + start, prefix, prefix_size) != 0) continue;
        memcpy(names[found], body + start, end - start);
        names[found][end - start] = 0;
        if (ankah_dots_valid_cuid(names[found])) ++found;
    }
    return found;
}
