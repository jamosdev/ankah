#include "ankah/http.h"
#include "header_names.h"
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

static int header_has_token(const ankah_request *request, enum ankah_header_kind kind,
                            const char *token) {
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        const char *p;
        if (!ankah_header_is(&request->headers[i], kind)) continue;
        p = request->headers[i].value;
        while (*p) {
            const char *start, *end;
            while (*p == ',' || *p == ' ' || *p == '\t') ++p;
            start = p;
            while (*p && *p != ',') ++p;
            end = p;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
            if (same_ascii_part(start, (size_t)(end - start), token)) return 1;
        }
    }
    return 0;
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
    unsigned char kind = ankah_header_name_kind(name, strlen(name));
    unsigned int i;
    for (i = 0; i < request->count; ++i) {
        if ((kind != ANKAH_HEADER_OTHER &&
             ankah_header_effective_kind(&request->headers[i]) == kind) ||
            (kind == ANKAH_HEADER_OTHER &&
             same_ascii(request->headers[i].name, name)))
            return request->headers[i].value;
    }
    return NULL;
}

int ankah_parse_request(const char *bytes, size_t length, ankah_request *out) {
    llhttp_t parser;
    llhttp_settings_t settings;
    parse_context context;
    llhttp_errno_t error;
    unsigned int i, host_count = 0, length_count = 0, encoding_count = 0;
    unsigned int expect_count = 0, upgrade_count = 0, type_count = 0;
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
        ankah_header *header = &out->headers[i];
        ankah_header_classify(header);
        if (header->kind == ANKAH_HEADER_HOST) {
            ++host_count;
            if (!header->value[0]) return -1;
        } else if (header->kind == ANKAH_HEADER_CONTENT_LENGTH) {
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
        } else if (header->kind == ANKAH_HEADER_TRANSFER_ENCODING) {
            ++encoding_count;
            if (!same_ascii(header->value, "chunked")) return -1;
        } else if (header->kind == ANKAH_HEADER_EXPECT) ++expect_count;
        else if (header->kind == ANKAH_HEADER_UPGRADE) ++upgrade_count;
        else if (header->kind == ANKAH_HEADER_CONTENT_TYPE) ++type_count;
    }
    if (host_count != 1 || length_count > 1 || encoding_count > 1 ||
        expect_count > 1 || upgrade_count > 1 || type_count > 1 ||
        (length_count && encoding_count)) return -1;
    out->content_length = body_length;
    out->has_body = length_count != 0 || encoding_count != 0;
    out->chunked = encoding_count != 0;
    out->websocket = strcmp(out->method, "GET") == 0 && !out->has_body &&
                     llhttp_get_upgrade(&parser) &&
                     ankah_header_value(out, "Upgrade") &&
                     same_ascii(ankah_header_value(out, "Upgrade"), "websocket") &&
                     header_has_token(out, ANKAH_HEADER_CONNECTION, "upgrade");
    return 0;
}

enum {
    CHUNK_SIZE,
    CHUNK_SIZE_LF,
    CHUNK_DATA,
    CHUNK_DATA_CR,
    CHUNK_DATA_LF,
    CHUNK_TRAILER,
    CHUNK_TRAILER_LF
};

static int chunk_hex(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int chunk_token(unsigned char value) {
    if ((value >= '0' && value <= '9') ||
        (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z')) return 1;
    return strchr("!#$%&'*+-.^_`|~", value) != NULL;
}

static int chunk_name_is(const char *value, size_t length, const char *name) {
    size_t i;
    if (length != strlen(name)) return 0;
    for (i = 0; i < length; ++i) {
        unsigned char left = (unsigned char)value[i];
        unsigned char right = (unsigned char)name[i];
        if (left >= 'A' && left <= 'Z') left = (unsigned char)(left + 32);
        if (right >= 'A' && right <= 'Z') right = (unsigned char)(right + 32);
        if (left != right) return 0;
    }
    return 1;
}

static int parse_chunk_size(ankah_chunked_body *body) {
    size_t value = 0, digits = 0, i = 0;
    int extension = 0;
    while (i < body->line_size) {
        unsigned char byte = (unsigned char)body->line[i++];
        int digit;
        if (!extension && byte == ';') {
            if (!digits) return -1;
            extension = 1;
            continue;
        }
        if (extension) {
            if (byte < 0x20 || byte > 0x7e) return -1;
            continue;
        }
        digit = chunk_hex(byte);
        if (digit < 0 || value > (SIZE_MAX - (size_t)digit) / 16) return -1;
        value = value * 16 + (size_t)digit;
        ++digits;
    }
    if (!digits) return -1;
    body->remaining = value;
    body->line_size = 0;
    return 0;
}

static int parse_chunk_trailer(const ankah_chunked_body *body) {
    size_t colon = 0, i;
    while (colon < body->line_size && body->line[colon] != ':') ++colon;
    if (!colon || colon == body->line_size) return -1;
    for (i = 0; i < colon; ++i)
        if (!chunk_token((unsigned char)body->line[i])) return -1;
    for (i = colon + 1; i < body->line_size; ++i) {
        unsigned char byte = (unsigned char)body->line[i];
        if ((byte < 0x20 && byte != '\t') || byte == 0x7f) return -1;
    }
    if (chunk_name_is(body->line, colon, "content-length") ||
        chunk_name_is(body->line, colon, "transfer-encoding") ||
        chunk_name_is(body->line, colon, "host") ||
        chunk_name_is(body->line, colon, "connection") ||
        chunk_name_is(body->line, colon, "trailer")) return -1;
    return 0;
}

void ankah_chunked_body_init(ankah_chunked_body *body) {
    memset(body, 0, sizeof(*body));
    body->state = CHUNK_SIZE;
}

int ankah_chunked_body_consume(ankah_chunked_body *body,
                               const char *bytes, size_t length,
                               size_t max_decoded, size_t *decoded) {
    size_t offset = 0, added = 0;
    if (decoded) *decoded = 0;
    if (!body || (!bytes && length) || body->complete) return -1;
    while (offset < length) {
        unsigned char byte = (unsigned char)bytes[offset];
        if (body->state == CHUNK_DATA) {
            size_t amount = length - offset;
            if (amount > body->remaining) amount = body->remaining;
            if (body->decoded > max_decoded || amount > max_decoded - body->decoded) {
                body->limit_exceeded = 1;
                return -1;
            }
            body->remaining -= amount;
            body->decoded += amount;
            added += amount;
            offset += amount;
            if (!body->remaining) body->state = CHUNK_DATA_CR;
            continue;
        }
        ++offset;
        if (body->state == CHUNK_SIZE) {
            if (byte == '\r') body->state = CHUNK_SIZE_LF;
            else if (byte == '\n' || body->line_size == sizeof(body->line) - 1) return -1;
            else body->line[body->line_size++] = (char)byte;
        } else if (body->state == CHUNK_SIZE_LF) {
            if (byte != '\n' || parse_chunk_size(body) != 0) return -1;
            body->state = body->remaining ? CHUNK_DATA : CHUNK_TRAILER;
        } else if (body->state == CHUNK_DATA_CR) {
            if (byte != '\r') return -1;
            body->state = CHUNK_DATA_LF;
        } else if (body->state == CHUNK_DATA_LF) {
            if (byte != '\n') return -1;
            body->state = CHUNK_SIZE;
        } else if (body->state == CHUNK_TRAILER) {
            if (byte == '\r') body->state = CHUNK_TRAILER_LF;
            else if (byte == '\n' || body->line_size == sizeof(body->line) - 1 ||
                     body->trailer_size == ANKAH_HEADER_LIMIT) return -1;
            else {
                body->line[body->line_size++] = (char)byte;
                ++body->trailer_size;
            }
        } else if (body->state == CHUNK_TRAILER_LF) {
            if (byte != '\n') return -1;
            if (!body->line_size) {
                body->complete = 1;
                if (offset != length) return -1;
            } else {
                if (parse_chunk_trailer(body) != 0) return -1;
                body->line_size = 0;
                body->state = CHUNK_TRAILER;
            }
        } else return -1;
    }
    if (decoded) *decoded = added;
    return body->complete ? 1 : 0;
}
