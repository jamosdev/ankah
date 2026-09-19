#ifndef ANKAH_PROXY_H
#define ANKAH_PROXY_H

#include "ankah/http.h"
#include <stddef.h>

#define ANKAH_MAX_TRUSTED_PROXIES 32

typedef struct {
    unsigned char address[16];
    unsigned int prefix;
    int family;
} ankah_network;

int ankah_parse_network(const char *text, ankah_network *out);
int ankah_normalize_ip(const char *text, char *out, size_t capacity);
int ankah_resolve_client_ip(const ankah_request *request, const char *peer,
                            const ankah_network *trusted, size_t trusted_count,
                            char *out, size_t capacity);

#endif
