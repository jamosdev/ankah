#include "ankah/proxy.h"
#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        ++failures;
    }
}

static void header(ankah_request *request, const char *name, const char *value) {
    ankah_header *item = &request->headers[request->count++];
    strcpy(item->name, name);
    strcpy(item->value, value);
}

int main(void) {
    ankah_network trusted[3];
    ankah_request request;
    char ip[64];
    check(ankah_parse_network("127.0.0.0/8", &trusted[0]) == 0, "parse IPv4 network");
    check(ankah_parse_network("10.0.0.0/8", &trusted[1]) == 0, "parse private network");
    check(ankah_parse_network("2001:db8::/32", &trusted[2]) == 0, "parse IPv6 network");
    check(ankah_parse_network("10.0.0.1/33", &trusted[0]) != 0, "reject bad prefix");
    check(ankah_parse_network("bad/8", &trusted[0]) != 0, "reject bad address");
    check(ankah_parse_network("10.0.0.1:80/8", &trusted[0]) != 0, "reject network port");
    check(ankah_parse_network("127.0.0.0/8", &trusted[0]) == 0, "restore network");

    memset(&request, 0, sizeof(request));
    header(&request, "X-Forwarded-For", "198.51.100.7, 10.1.2.3");
    check(ankah_resolve_client_ip(&request, "127.0.0.1", trusted, 3,
                                  ip, sizeof(ip)) == 0 &&
          strcmp(ip, "198.51.100.7") == 0, "walk trusted XFF chain");
    check(ankah_resolve_client_ip(&request, "192.0.2.10", trusted, 3,
                                  ip, sizeof(ip)) == 0 &&
          strcmp(ip, "192.0.2.10") == 0, "ignore XFF from other peer");
    check(ankah_resolve_client_ip(&request, "::ffff:127.0.0.1", trusted, 3,
                                  ip, sizeof(ip)) == 0 &&
          strcmp(ip, "198.51.100.7") == 0, "normalize mapped peer");

    memset(&request, 0, sizeof(request));
    header(&request, "Forwarded", "for=198.51.100.8;proto=https, for=10.2.3.4");
    header(&request, "X-Forwarded-For", "203.0.113.9");
    check(ankah_resolve_client_ip(&request, "127.0.0.1", trusted, 3,
                                  ip, sizeof(ip)) == 0 &&
          strcmp(ip, "198.51.100.8") == 0, "prefer Forwarded header");

    memset(&request, 0, sizeof(request));
    header(&request, "Forwarded", "for=\"[2001:4860::1]:443\", for=\"[2001:db8::2]\"");
    check(ankah_resolve_client_ip(&request, "2001:db8::1", trusted, 3,
                                  ip, sizeof(ip)) == 0 &&
          strcmp(ip, "2001:4860::1") == 0, "parse quoted IPv6 chain");

    memset(&request, 0, sizeof(request));
    header(&request, "Forwarded", "for=_hidden");
    check(ankah_resolve_client_ip(&request, "127.0.0.1", trusted, 3,
                                  ip, sizeof(ip)) != 0, "reject obfuscated address");
    return failures ? 1 : 0;
}
