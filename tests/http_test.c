#include "ankah/http.h"
#include <stdio.h>
#include <string.h>

static int expect(int truth, const char *name) {
    if (!truth) fprintf(stderr, "FAIL: %s\n", name);
    return truth ? 0 : 1;
}

int main(void) {
    const char *good = "GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const char *smuggle = "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
    const char *duplicate = "GET / HTTP/1.1\r\nHost: example.test\r\nHost: other.test\r\n\r\n";
    const char *upgrade = "GET /ws HTTP/1.1\r\nHost: example.test\r\n"
                          "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    ankah_request request;
    int failures = 0;
    failures += expect(ankah_parse_request(good, strlen(good), &request) == 0, "valid request");
    failures += expect(strcmp(request.target, "/hello") == 0, "target");
    failures += expect(ankah_parse_request(smuggle, strlen(smuggle), &request) != 0,
                       "conflicting framing");
    failures += expect(ankah_parse_request(duplicate, strlen(duplicate), &request) != 0,
                       "duplicate host");
    failures += expect(ankah_parse_request(upgrade, strlen(upgrade), &request) == 0 &&
                       request.websocket, "websocket upgrade");
    return failures ? 1 : 0;
}
