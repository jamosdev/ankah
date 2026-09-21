#include "header_names.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    enum ankah_header_kind kind;
} expected_header;

static const expected_header expected[] = {
    {":authority", ANKAH_HEADER_PSEUDO_AUTHORITY},
    {":method", ANKAH_HEADER_PSEUDO_METHOD},
    {":path", ANKAH_HEADER_PSEUDO_PATH},
    {":scheme", ANKAH_HEADER_PSEUDO_SCHEME},
    {"accept-encoding", ANKAH_HEADER_ACCEPT_ENCODING},
    {"authorization", ANKAH_HEADER_AUTHORIZATION},
    {"connection", ANKAH_HEADER_CONNECTION},
    {"content-length", ANKAH_HEADER_CONTENT_LENGTH},
    {"content-type", ANKAH_HEADER_CONTENT_TYPE},
    {"cookie", ANKAH_HEADER_COOKIE},
    {"expect", ANKAH_HEADER_EXPECT},
    {"forwarded", ANKAH_HEADER_FORWARDED},
    {"host", ANKAH_HEADER_HOST},
    {"http2-settings", ANKAH_HEADER_HTTP2_SETTINGS},
    {"if-modified-since", ANKAH_HEADER_IF_MODIFIED_SINCE},
    {"if-none-match", ANKAH_HEADER_IF_NONE_MATCH},
    {"if-range", ANKAH_HEADER_IF_RANGE},
    {"keep-alive", ANKAH_HEADER_KEEP_ALIVE},
    {"proxy-authorization", ANKAH_HEADER_PROXY_AUTHORIZATION},
    {"proxy-connection", ANKAH_HEADER_PROXY_CONNECTION},
    {"range", ANKAH_HEADER_RANGE},
    {"te", ANKAH_HEADER_TE},
    {"trailer", ANKAH_HEADER_TRAILER},
    {"transfer-encoding", ANKAH_HEADER_TRANSFER_ENCODING},
    {"upgrade", ANKAH_HEADER_UPGRADE},
    {"user-agent", ANKAH_HEADER_USER_AGENT},
    {"x-ankah-internal-key", ANKAH_HEADER_X_ANKAH_INTERNAL_KEY},
    {"x-ankah-internal-peer", ANKAH_HEADER_X_ANKAH_INTERNAL_PEER},
    {"x-forwarded-for", ANKAH_HEADER_X_FORWARDED_FOR},
    {"x-real-ip", ANKAH_HEADER_X_REAL_IP}
};

static int failures;

static void check(int condition, const char *message, const char *name) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s: %s\n", message, name);
        ++failures;
    }
}

int main(void) {
    char folded[64];
    ankah_header header = {{0}, {0}, 0};
    ankah_header saved;
    char embedded[] = {'h', 'o', 0, 's', 't'};
    char oversized[ANKAH_MAX_FIELD];
    size_t i, j;
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
        size_t length = strlen(expected[i].name);
        check(ankah_header_name_kind(expected[i].name, length) == expected[i].kind,
              "lowercase lookup", expected[i].name);
        memcpy(folded, expected[i].name, length + 1);
        for (j = 0; j < length; ++j)
            if (folded[j] >= 'a' && folded[j] <= 'z') folded[j] -= 'a' - 'A';
        check(ankah_header_name_kind(folded, length) == expected[i].kind,
              "uppercase lookup", expected[i].name);
    }
    check(ankah_header_name_kind("", 0) == ANKAH_HEADER_OTHER,
          "empty lookup", "empty");
    check(ankah_header_name_kind("hostile", 7) == ANKAH_HEADER_OTHER,
          "near miss", "hostile");
    check(ankah_header_name_kind(":path-extra", 5) == ANKAH_HEADER_PSEUDO_PATH,
          "bounded lookup", ":path");
    check(ankah_header_name_kind(":path-extra", strlen(":path-extra")) ==
              ANKAH_HEADER_OTHER,
          "full-length near miss", ":path-extra");
    check(ankah_header_set_name(&header, "Host", 4) == 0 &&
              ankah_header_effective_kind(&header) == ANKAH_HEADER_HOST,
          "setter classification", "Host");
    check(ankah_header_set_name(&header, "X-Custom", 8) == 0 &&
              ankah_header_effective_kind(&header) == ANKAH_HEADER_OTHER,
          "setter reclassification", "X-Custom");
    check(ankah_header_set_name(&header, "Range", 5) == 0 &&
              ankah_header_effective_kind(&header) == ANKAH_HEADER_RANGE,
          "setter recognized reclassification", "Range");
    saved = header;
    memset(oversized, 'a', sizeof(oversized));
    check(ankah_header_set_name(&header, oversized, sizeof(oversized)) != 0 &&
              memcmp(&header, &saved, sizeof(header)) == 0,
          "reject oversized name unchanged", "oversized");
    check(ankah_header_set_name(&header, embedded, sizeof(embedded)) != 0 &&
              memcmp(&header, &saved, sizeof(header)) == 0,
          "reject embedded NUL unchanged", "embedded NUL");
    check(ankah_header_set_name(&header, "", 0) != 0 &&
              memcmp(&header, &saved, sizeof(header)) == 0,
          "reject empty name unchanged", "empty");
    check(ankah_header_set_name(&header, NULL, 1) != 0 &&
              memcmp(&header, &saved, sizeof(header)) == 0,
          "reject null name unchanged", "null");
    check(ankah_header_set_name(NULL, "Host", 4) != 0,
          "reject null header", "null");
    return failures ? 1 : 0;
}
