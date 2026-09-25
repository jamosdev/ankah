#ifndef ANKAH_HTTP_H
#define ANKAH_HTTP_H

#include <stddef.h>

#define ANKAH_HEADER_LIMIT 16384
#define ANKAH_MAX_HEADERS 64
#define ANKAH_MAX_FIELD 128
#define ANKAH_MAX_VALUE 4096
#define ANKAH_MAX_TARGET 2048
#define ANKAH_CHUNK_LINE_LIMIT 4096

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

typedef struct {
    size_t remaining;
    size_t decoded;
    size_t trailer_size;
    size_t line_size;
    unsigned char state;
    int complete;
    int limit_exceeded;
    char line[ANKAH_CHUNK_LINE_LIMIT];
} ankah_chunked_body;

/* Pass exactly one complete header block ending in CRLFCRLF. */
int ankah_parse_request(const char *bytes, size_t length, ankah_request *out);
void ankah_chunked_body_init(ankah_chunked_body *body);
/* Validate one piece of HTTP/1.1 chunked wire data. Returns 1 after the
 * terminating empty trailer line, 0 while more input is required, and -1 for
 * invalid framing or a decoded body larger than max_decoded. */
int ankah_chunked_body_consume(ankah_chunked_body *body,
                               const char *bytes, size_t length,
                               size_t max_decoded, size_t *decoded);
/* Set exactly length name bytes and refresh the internal classification cache.
 * The bytes need not be NUL terminated. Null, empty, embedded-NUL, or oversized
 * names return -1 without changing header. */
int ankah_header_set_name(ankah_header *header, const char *name, size_t length);
const char *ankah_header_value(const ankah_request *request, const char *name);

#endif
