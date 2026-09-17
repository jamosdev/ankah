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
const char *ankah_header_value(const ankah_request *request, const char *name);

#endif
