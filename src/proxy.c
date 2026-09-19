#include "ankah/proxy.h"
#include <uv.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHAIN 64

typedef struct {
    unsigned char bytes[16];
    int family;
} ip_address;

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

static int parse_ip_text(const char *text, size_t length, ip_address *out) {
    char value[128];
    const char *start = text, *end = text + length;
    const char *colon;
    size_t size;
    while (start < end && (*start == ' ' || *start == '\t')) ++start;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
    if (start == end) return -1;
    if (*start == '"') {
        if (end - start < 2 || end[-1] != '"') return -1;
        ++start;
        --end;
        if (memchr(start, '\\', (size_t)(end - start))) return -1;
    }
    if (start < end && *start == '[') {
        const char *close = memchr(start, ']', (size_t)(end - start));
        if (!close) return -1;
        if (close + 1 < end) {
            const char *p;
            if (close[1] != ':' || close + 2 == end) return -1;
            for (p = close + 2; p < end; ++p) if (!isdigit((unsigned char)*p)) return -1;
        }
        ++start;
        end = close;
    } else {
        colon = memchr(start, ':', (size_t)(end - start));
        if (colon && memchr(start, '.', (size_t)(end - start)) &&
            !memchr(colon + 1, ':', (size_t)(end - colon - 1))) {
            const char *p;
            if (colon + 1 == end) return -1;
            for (p = colon + 1; p < end; ++p) if (!isdigit((unsigned char)*p)) return -1;
            end = colon;
        }
    }
    size = (size_t)(end - start);
    if (!size || size >= sizeof(value)) return -1;
    memcpy(value, start, size);
    value[size] = 0;
    memset(out, 0, sizeof(*out));
    if (uv_inet_pton(AF_INET, value, out->bytes) == 0) {
        out->family = AF_INET;
        return 0;
    }
    if (uv_inet_pton(AF_INET6, value, out->bytes) == 0) {
        static const unsigned char mapped_prefix[12] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
        };
        if (memcmp(out->bytes, mapped_prefix, sizeof(mapped_prefix)) == 0) {
            memmove(out->bytes, out->bytes + 12, 4);
            memset(out->bytes + 4, 0, 12);
            out->family = AF_INET;
            return 0;
        }
        out->family = AF_INET6;
        return 0;
    }
    return -1;
}

static int format_ip(const ip_address *ip, char *out, size_t capacity) {
    return uv_inet_ntop(ip->family, ip->bytes, out, capacity);
}

int ankah_normalize_ip(const char *text, char *out, size_t capacity) {
    ip_address ip;
    if (!text || !out || !capacity || parse_ip_text(text, strlen(text), &ip) != 0) return -1;
    return format_ip(&ip, out, capacity);
}

int ankah_parse_network(const char *text, ankah_network *out) {
    char address[128], *slash, *end;
    const char *digit;
    ip_address ip;
    unsigned long prefix;
    size_t length, bytes, i;
    unsigned int remainder;
    if (!text || !out || strlen(text) >= sizeof(address)) return -1;
    strcpy(address, text);
    slash = strrchr(address, '/');
    if (!slash || slash == address || !slash[1]) return -1;
    *slash++ = 0;
    if (address[0] == '[' || (strchr(address, '.') && strchr(address, ':'))) return -1;
    for (digit = slash; *digit; ++digit)
        if (!isdigit((unsigned char)*digit)) return -1;
    if (parse_ip_text(address, strlen(address), &ip) != 0) return -1;
    prefix = strtoul(slash, &end, 10);
    if (*end || prefix > (ip.family == AF_INET ? 32UL : 128UL)) return -1;
    memset(out, 0, sizeof(*out));
    out->family = ip.family;
    out->prefix = (unsigned int)prefix;
    memcpy(out->address, ip.bytes, sizeof(out->address));
    length = ip.family == AF_INET ? 4 : 16;
    bytes = out->prefix / 8;
    remainder = out->prefix % 8;
    if (remainder && bytes < length) {
        out->address[bytes] &= (unsigned char)(0xffU << (8U - remainder));
        ++bytes;
    }
    for (i = bytes; i < length; ++i) out->address[i] = 0;
    return 0;
}

static int network_contains(const ankah_network *network, const ip_address *ip) {
    size_t bytes;
    unsigned int remainder;
    if (network->family != ip->family) return 0;
    bytes = network->prefix / 8;
    remainder = network->prefix % 8;
    if (bytes && memcmp(network->address, ip->bytes, bytes) != 0) return 0;
    if (remainder) {
        unsigned char mask = (unsigned char)(0xffU << (8U - remainder));
        if ((network->address[bytes] & mask) != (ip->bytes[bytes] & mask)) return 0;
    }
    return 1;
}

static int is_trusted(const ip_address *ip, const ankah_network *trusted, size_t count) {
    size_t i;
    for (i = 0; i < count; ++i) if (network_contains(&trusted[i], ip)) return 1;
    return 0;
}

static int append_chain(ip_address *chain, size_t *count,
                        const char *text, size_t length) {
    if (*count == MAX_CHAIN || parse_ip_text(text, length, &chain[*count]) != 0) return -1;
    ++*count;
    return 0;
}

static int parse_xff(const ankah_request *request, ip_address *chain, size_t *count) {
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        const char *p, *start;
        if (!same_ascii_part(request->headers[i].name,
                             strlen(request->headers[i].name), "X-Forwarded-For")) continue;
        p = request->headers[i].value;
        while (*p) {
            start = p;
            while (*p && *p != ',') ++p;
            if (append_chain(chain, count, start, (size_t)(p - start)) != 0) return -1;
            if (*p == ',') ++p;
        }
    }
    return *count ? 0 : -1;
}

static int forwarded_element(const char *start, const char *end,
                             ip_address *chain, size_t *count) {
    const char *p = start;
    int found = 0;
    while (p < end) {
        const char *name, *name_end, *value, *value_end;
        while (p < end && (*p == ' ' || *p == '\t' || *p == ';')) ++p;
        if (p == end) break;
        name = p;
        while (p < end && *p != '=' && *p != ';') ++p;
        if (p == end || *p != '=') return -1;
        name_end = p++;
        while (name_end > name && (name_end[-1] == ' ' || name_end[-1] == '\t')) --name_end;
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        value = p;
        if (p < end && *p == '"') {
            ++p;
            while (p < end) {
                if (*p == '\\') {
                    p += 2;
                    if (p > end) return -1;
                } else if (*p++ == '"') break;
            }
            if (p > end || p[-1] != '"') return -1;
            value_end = p;
        } else {
            while (p < end && *p != ';') ++p;
            value_end = p;
            while (value_end > value && (value_end[-1] == ' ' || value_end[-1] == '\t')) --value_end;
        }
        if (same_ascii_part(name, (size_t)(name_end - name), "for")) {
            if (found || append_chain(chain, count, value,
                                      (size_t)(value_end - value)) != 0) return -1;
            found = 1;
        }
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        if (p < end && *p != ';') return -1;
    }
    return found ? 0 : -1;
}

static int parse_forwarded_value(const char *value, ip_address *chain, size_t *count) {
    const char *p = value, *start = value;
    int quoted = 0, escaped = 0;
    for (;;) {
        char c = *p;
        if (quoted) {
            if (escaped) escaped = 0;
            else if (c == '\\') escaped = 1;
            else if (c == '"') quoted = 0;
            else if (!c) return -1;
        } else if (c == '"') quoted = 1;
        else if (c == ',' || !c) {
            if (forwarded_element(start, p, chain, count) != 0) return -1;
            if (!c) return 0;
            start = p + 1;
        }
        ++p;
    }
}

static int parse_forwarded(const ankah_request *request, ip_address *chain, size_t *count) {
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        if (!same_ascii_part(request->headers[i].name,
                             strlen(request->headers[i].name), "Forwarded")) continue;
        if (parse_forwarded_value(request->headers[i].value, chain, count) != 0) return -1;
    }
    return *count ? 0 : -1;
}

int ankah_resolve_client_ip(const ankah_request *request, const char *peer,
                            const ankah_network *trusted, size_t trusted_count,
                            char *out, size_t capacity) {
    ip_address direct, chain[MAX_CHAIN], selected;
    size_t count = 0, i;
    int has_forwarded = 0, has_xff = 0;
    unsigned int h;
    if (!request || !peer || !out || !capacity ||
        parse_ip_text(peer, strlen(peer), &direct) != 0) return -1;
    selected = direct;
    if (!is_trusted(&direct, trusted, trusted_count)) return format_ip(&direct, out, capacity);
    for (h = 0; h < request->count; ++h) {
        size_t name_length = strlen(request->headers[h].name);
        if (same_ascii_part(request->headers[h].name, name_length, "Forwarded")) has_forwarded = 1;
        if (same_ascii_part(request->headers[h].name, name_length, "X-Forwarded-For")) has_xff = 1;
    }
    if (has_forwarded) {
        if (parse_forwarded(request, chain, &count) != 0) return -1;
    } else if (has_xff) {
        if (parse_xff(request, chain, &count) != 0) return -1;
    } else return format_ip(&direct, out, capacity);
    for (i = count; i > 0; --i) {
        selected = chain[i - 1];
        if (!is_trusted(&selected, trusted, trusted_count)) break;
    }
    return format_ip(&selected, out, capacity);
}
