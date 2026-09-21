#ifndef ANKAH_HTTP_H
#define ANKAH_HTTP_H

#include <stddef.h>

#define ANKAH_HEADER_LIMIT 16384
#define ANKAH_MAX_HEADERS 64
#define ANKAH_MAX_FIELD 128
#define ANKAH_MAX_VALUE 4096
#define ANKAH_MAX_TARGET 2048

typedef struct {
    char name[ANKAH_MAX_FIELD];
    char value[ANKAH_MAX_VALUE];
    /* Internal classification cache. Use ankah_header_set_name to change name. */
    unsigned char kind;
} ankah_header;

typedef struct {
    char method[16];
    char target[ANKAH_MAX_TARGET];
    ankah_header headers[ANKAH_MAX_HEADERS];
    unsigned int count;
    int websocket;
    int has_body;
    int chunked;
    size_t content_length;
} ankah_request;

/* Pass exactly one complete header block ending in CRLFCRLF. */
int ankah_parse_request(const char *bytes, size_t length, ankah_request *out);
/* Set exactly length name bytes and refresh the internal classification cache.
 * The bytes need not be NUL terminated. Null, empty, embedded-NUL, or oversized
 * names return -1 without changing header. */
int ankah_header_set_name(ankah_header *header, const char *name, size_t length);
const char *ankah_header_value(const ankah_request *request, const char *name);

#endif
