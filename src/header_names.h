#ifndef ANKAH_HEADER_NAMES_H
#define ANKAH_HEADER_NAMES_H

#include "ankah/http.h"
#include <stddef.h>
#include <string.h>

enum ankah_header_kind {
    ANKAH_HEADER_UNCLASSIFIED,
    ANKAH_HEADER_OTHER,
    ANKAH_HEADER_PSEUDO_AUTHORITY,
    ANKAH_HEADER_PSEUDO_METHOD,
    ANKAH_HEADER_PSEUDO_PATH,
    ANKAH_HEADER_PSEUDO_SCHEME,
    ANKAH_HEADER_ACCEPT_ENCODING,
    ANKAH_HEADER_ACCEPT_LANGUAGE,
    ANKAH_HEADER_AUTHORIZATION,
    ANKAH_HEADER_CONNECTION,
    ANKAH_HEADER_CONTENT_LENGTH,
    ANKAH_HEADER_CONTENT_TYPE,
    ANKAH_HEADER_COOKIE,
    ANKAH_HEADER_EXPECT,
    ANKAH_HEADER_FORWARDED,
    ANKAH_HEADER_HOST,
    ANKAH_HEADER_HTTP2_SETTINGS,
    ANKAH_HEADER_IF_MODIFIED_SINCE,
    ANKAH_HEADER_IF_NONE_MATCH,
    ANKAH_HEADER_IF_RANGE,
    ANKAH_HEADER_KEEP_ALIVE,
    ANKAH_HEADER_PROXY_AUTHORIZATION,
    ANKAH_HEADER_PROXY_CONNECTION,
    ANKAH_HEADER_RANGE,
    ANKAH_HEADER_TE,
    ANKAH_HEADER_TRAILER,
    ANKAH_HEADER_TRANSFER_ENCODING,
    ANKAH_HEADER_UPGRADE,
    ANKAH_HEADER_USER_AGENT,
    ANKAH_HEADER_X_ANKAH_INTERNAL_KEY,
    ANKAH_HEADER_X_ANKAH_INTERNAL_PEER,
    ANKAH_HEADER_X_FORWARDED_FOR,
    ANKAH_HEADER_X_REAL_IP
};

struct ankah_header_keyword {
    const char *name;
    enum ankah_header_kind kind;
};

const struct ankah_header_keyword *ankah_header_lookup(const char *name,
                                                        size_t length);

/* length defines the complete byte sequence examined; bytes after it are ignored. */
static inline unsigned char ankah_header_name_kind(const char *name,
                                                    size_t length) {
    const struct ankah_header_keyword *keyword = ankah_header_lookup(name, length);
    return (unsigned char)(keyword ? keyword->kind : ANKAH_HEADER_OTHER);
}

static inline void ankah_header_classify(ankah_header *header) {
    header->kind = ankah_header_name_kind(header->name, strlen(header->name));
}

static inline unsigned char ankah_header_effective_kind(const ankah_header *header) {
    return header->kind == ANKAH_HEADER_UNCLASSIFIED ?
        ankah_header_name_kind(header->name, strlen(header->name)) : header->kind;
}

static inline int ankah_header_is(const ankah_header *header,
                                  enum ankah_header_kind kind) {
    return ankah_header_effective_kind(header) == (unsigned char)kind;
}

#endif
