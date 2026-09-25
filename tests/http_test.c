#include "ankah/http.h"
#include <stdio.h>
#include <string.h>

static int expect(int truth, const char *name) {
    if (!truth) fprintf(stderr, "FAIL: %s\n", name);
    return truth ? 0 : 1;
}

int main(void) {
    const char *good = "GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const char *smuggle = "POST / HTTP/1.1\r\nhOsT: example.test\r\ncontent-LENGTH: 5\r\n"
                           "TRANSFER-encoding: chunked\r\n\r\n";
    const char *duplicate = "GET / HTTP/1.1\r\nHost: example.test\r\nhOsT: other.test\r\n\r\n";
    const char *upgrade = "GET /ws HTTP/1.1\r\nhOsT: example.test\r\n"
                          "cOnNeCtIoN: Upgrade\r\nuPgRaDe: websocket\r\n\r\n";
    const char *post_upgrade = "POST /ws HTTP/1.1\r\nHost: example.test\r\n"
                               "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                               "Content-Length: 0\r\n\r\n";
    const char *missing_connection = "GET /ws HTTP/1.1\r\nHost: example.test\r\n"
                                     "Upgrade: websocket\r\n\r\n";
    const char *duplicate_expect = "POST / HTTP/1.1\r\nHost: example.test\r\n"
                                   "Content-Length: 0\r\nExpect: 100-continue\r\n"
                                   "Expect: other\r\n\r\n";
    const char *manual;
    const char *chunk_rest = "\nWiki\r\n5\r\npedia\r\n0\r\nX-Result: yes\r\n\r\n";
    const char *bad_chunk = "3\r\nabc\n0\r\n\r\n";
    const char *large_chunk = "5\r\nhello\r\n0\r\n\r\n";
    const char *bad_trailer = "0\r\nContent-Length: 2\r\n\r\n";
    ankah_request request;
    ankah_chunked_body chunks;
    size_t decoded;
    int failures = 0;
    failures += expect(ankah_parse_request(good, strlen(good), &request) == 0, "valid request");
    failures += expect(strcmp(request.target, "/hello") == 0, "target");
    failures += expect(ankah_parse_request(smuggle, strlen(smuggle), &request) != 0,
                       "conflicting framing");
    failures += expect(ankah_parse_request(duplicate, strlen(duplicate), &request) != 0,
                       "duplicate host");
    failures += expect(ankah_parse_request(upgrade, strlen(upgrade), &request) == 0 &&
                       request.websocket, "websocket upgrade");
    failures += expect(ankah_parse_request(post_upgrade, strlen(post_upgrade), &request) == 0 &&
                       !request.websocket, "POST is not a websocket upgrade");
    failures += expect(ankah_parse_request(missing_connection, strlen(missing_connection),
                                           &request) == 0 && !request.websocket,
                       "upgrade requires connection token");
    failures += expect(ankah_parse_request(duplicate_expect, strlen(duplicate_expect),
                                           &request) != 0,
                       "duplicate expectation");
    memset(&request, 0, sizeof(request));
    request.count = 1;
    failures += expect(ankah_header_set_name(&request.headers[0], "hOsT", 4) == 0,
                       "set manual header name");
    strcpy(request.headers[0].value, "manual.test");
    manual = ankah_header_value(&request, "Host");
    failures += expect(manual && strcmp(manual, "manual.test") == 0, "classified lookup");
    failures += expect(ankah_header_set_name(&request.headers[0], "X-Custom", 8) == 0,
                       "replace manual header name");
    manual = ankah_header_value(&request, "x-custom");
    failures += expect(manual && strcmp(manual, "manual.test") == 0,
                       "unknown header lookup");
    ankah_chunked_body_init(&chunks);
    failures += expect(ankah_chunked_body_consume(&chunks, "4;ok=yes\r", 9, 64,
                                                   &decoded) == 0 && decoded == 0,
                       "split chunk size");
    failures += expect(ankah_chunked_body_consume(&chunks, chunk_rest, strlen(chunk_rest),
                                                   64, &decoded) == 1 && decoded == 9 &&
                                                   chunks.decoded == 9,
                       "chunked body and trailer");
    ankah_chunked_body_init(&chunks);
    failures += expect(ankah_chunked_body_consume(&chunks, bad_chunk, strlen(bad_chunk),
                                                   64, &decoded) == -1,
                       "invalid chunk delimiter");
    ankah_chunked_body_init(&chunks);
    failures += expect(ankah_chunked_body_consume(&chunks, large_chunk, strlen(large_chunk),
                                                   4, &decoded) == -1 &&
                       chunks.limit_exceeded,
                       "chunk decoded limit");
    ankah_chunked_body_init(&chunks);
    failures += expect(ankah_chunked_body_consume(&chunks, bad_trailer, strlen(bad_trailer),
                                                   64, &decoded) == -1,
                       "forbidden chunk trailer");
    return failures ? 1 : 0;
}
