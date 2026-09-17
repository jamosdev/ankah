#include "ankah/http.h"
#include <llhttp.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    ankah_request *request;
    int stage;
    int overflow;
    int complete;
} parse_context;

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

static int append(char *destination, size_t capacity, const char *part, size_t length) {
    size_t old = strlen(destination);
    if (length >= capacity || old >= capacity - length) return -1;
    memcpy(destination + old, part, length);
    destination[old + length] = 0;
    return 0;
}

static int on_url(llhttp_t *parser, const char *at, size_t length) {
    parse_context *context = (parse_context *)parser->data;
    return append(context->request->target, ANKAH_MAX_TARGET, at, length);
}

static int on_field(llhttp_t *parser, const char *at, size_t length) {
    parse_context *context = (parse_context *)parser->data;
    if (context->stage == 2) ++context->request->count;
    if (context->request->count >= ANKAH_MAX_HEADERS) return -1;
    context->stage = 1;
    return append(context->request->headers[context->request->count].name,
                  ANKAH_MAX_FIELD, at, length);
}

static int on_value(llhttp_t *parser, const char *at, size_t length) {
    parse_context *context = (parse_context *)parser->data;
    if (context->stage != 1 && context->stage != 2) return -1;
    context->stage = 2;
    return append(context->request->headers[context->request->count].value,
                  ANKAH_MAX_VALUE, at, length);
}

static int on_complete_headers(llhttp_t *parser) {
    parse_context *context = (parse_context *)parser->data;
    const char *method = llhttp_method_name((llhttp_method_t)llhttp_get_method(parser));
    if (context->stage == 2) ++context->request->count;
    if (!method || strlen(method) >= sizeof(context->request->method)) return -1;
    strcpy(context->request->method, method);
    context->complete = 1;
    return 0;
}

const char *ankah_header_value(const ankah_request *request, const char *name) {
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        if (same_ascii(request->headers[i].name, name)) return request->headers[i].value;
    }
    return NULL;
}

int ankah_parse_request(const char *bytes, size_t length, ankah_request *out) {
    llhttp_t parser;
    llhttp_settings_t settings;
    parse_context context;
    llhttp_errno_t error;
    unsigned int i, host_count = 0, length_count = 0, encoding_count = 0;
    size_t body_length = 0;
    if (!bytes || !out || length < 4 || length > ANKAH_HEADER_LIMIT ||
        memcmp(bytes + length - 4, "\r\n\r\n", 4) != 0) return -1;
    memset(out, 0, sizeof(*out));
    memset(&context, 0, sizeof(context));
    context.request = out;
    llhttp_settings_init(&settings);
    settings.on_url = on_url;
    settings.on_header_field = on_field;
    settings.on_header_value = on_value;
    settings.on_headers_complete = on_complete_headers;
    llhttp_init(&parser, HTTP_REQUEST, &settings);
    parser.data = &context;
    error = llhttp_execute(&parser, bytes, length);
    if ((error != HPE_OK && error != HPE_PAUSED_UPGRADE) || !context.complete ||
        out->target[0] != '/' || strcmp(out->method, "CONNECT") == 0) return -1;
    for (i = 0; i < out->count; ++i) {
        const ankah_header *header = &out->headers[i];
        if (same_ascii(header->name, "Host")) {
            ++host_count;
            if (!header->value[0]) return -1;
        } else if (same_ascii(header->name, "Content-Length")) {
            size_t j;
            ++length_count;
            if (!header->value[0]) return -1;
            for (j = 0; header->value[j]; ++j) {
                unsigned int digit;
                if (header->value[j] < '0' || header->value[j] > '9') return -1;
                digit = (unsigned int)(header->value[j] - '0');
                if (body_length > (SIZE_MAX - digit) / 10) return -1;
                body_length = body_length * 10 + digit;
            }
        } else if (same_ascii(header->name, "Transfer-Encoding")) {
            ++encoding_count;
            if (!same_ascii(header->value, "chunked")) return -1;
        }
    }
    if (host_count != 1 || length_count > 1 || encoding_count > 1 ||
        (length_count && encoding_count)) return -1;
    out->content_length = body_length;
    out->has_body = length_count != 0 || encoding_count != 0;
    out->chunked = encoding_count != 0;
    out->websocket = llhttp_get_upgrade(&parser) &&
                     ankah_header_value(out, "Upgrade") &&
                     same_ascii(ankah_header_value(out, "Upgrade"), "websocket");
    return 0;
}
