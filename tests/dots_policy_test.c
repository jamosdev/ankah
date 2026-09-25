#include "dots_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S UINT64_C(1000000000)

static void check(int condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "dots_policy check failed: %s\n", what);
        exit(1);
    }
}

static ankah_dots_tracker tracker;

int main(void) {
    char text[2048], names[4][ANKAH_DOTS_NAME_MAX];
    unsigned int i;
    int hit;

    /* Threshold 5 within a 3 second window. */
    for (i = 0; i < 4; ++i) {
        hit = ankah_dots_tracker_hit(&tracker, "192.0.2.1", i * S / 2, 5, 3 * S);
        check(!hit, "below threshold");
    }
    hit = ankah_dots_tracker_hit(&tracker, "192.0.2.1", 2 * S, 5, 3 * S);
    check(hit, "threshold reached");
    hit = ankah_dots_tracker_hit(&tracker, "192.0.2.1", 2 * S + 1, 5, 3 * S);
    check(!hit, "history cleared after escalation");

    /* Requests spread wider than the window never escalate. */
    for (i = 0; i < 20; ++i) {
        hit = ankah_dots_tracker_hit(&tracker, "192.0.2.2", i * S, 5, 3 * S);
        check(!hit, "slow requests stay under the window threshold");
    }
    /* Counting is per address. */
    for (i = 0; i < 4; ++i) {
        hit = ankah_dots_tracker_hit(&tracker, "192.0.2.3", 100 * S, 5, 3 * S);
        check(!hit, "first address below threshold");
        hit = ankah_dots_tracker_hit(&tracker, "192.0.2.4", 100 * S, 5, 3 * S);
        check(!hit, "second address below threshold");
    }
    hit = ankah_dots_tracker_hit(&tracker, "192.0.2.3", 100 * S, 5, 3 * S);
    check(hit, "first address escalates on its own count");

    /* The table is bounded; filling it evicts old entries. */
    for (i = 0; i < ANKAH_DOTS_TRACKED + 8; ++i) {
        char ip[64];
        snprintf(ip, sizeof(ip), "2001:db8::%x", i);
        hit = ankah_dots_tracker_hit(&tracker, ip, (200 + i) * S, 5, 3 * S);
        check(!hit, "single request per address");
    }
    hit = ankah_dots_tracker_hit(&tracker, "192.0.2.4", 5000 * S, 5, 3 * S);
    check(!hit, "evicted history does not carry over");
    hit = ankah_dots_tracker_hit(&tracker, "", 0, 5, 3 * S);
    check(!hit, "empty address ignored");
    hit = ankah_dots_tracker_hit(&tracker, "192.0.2.9", 0, 0, 3 * S);
    check(!hit, "zero threshold rejected");

    check(ankah_dots_acl_name("172.30.0.20", text, sizeof(text)) == 0, "v4 name");
    check(strcmp(text, "ankah-172-30-0-20") == 0, "v4 name text");
    check(ankah_dots_acl_name("2001:db8::1", text, sizeof(text)) == 0, "v6 name");
    check(strcmp(text, "ankah-2001-db8--1") == 0, "v6 name text");
    check(ankah_dots_acl_name("1.2.3.4\"x", text, sizeof(text)) != 0, "hostile name rejected");

    check(ankah_dots_acl_body("ankah-172-30-0-20", "172.30.0.20", "172.30.0.11/32", 80,
                              text, sizeof(text)) > 0, "v4 body");
    check(strcmp(text,
        "{\"ietf-dots-data-channel:acls\":{\"acl\":[{\"name\":\"ankah-172-30-0-20\","
        "\"type\":\"ipv4-acl-type\",\"activation-type\":\"immediate\",\"aces\":{\"ace\":[{"
        "\"name\":\"block\",\"matches\":{\"ipv4\":{\"source-ipv4-network\":\"172.30.0.20/32\","
        "\"destination-ipv4-network\":\"172.30.0.11/32\",\"protocol\":6},\"tcp\":{"
        "\"destination-port-range-or-operator\":{\"operator\":\"eq\",\"port\":80}}},"
        "\"actions\":{\"forwarding\":\"drop\"}}]}}]}}") == 0, "v4 body text");
    check(ankah_dots_acl_body("ankah-2001-db8--1", "2001:db8::1", "2001:db8:1::/64", 443,
                              text, sizeof(text)) > 0, "v6 body");
    check(strstr(text, "\"source-ipv6-network\":\"2001:db8::1/128\"") != NULL, "v6 source");
    check(strstr(text, "\"type\":\"ipv6-acl-type\"") != NULL, "v6 type");
    check(ankah_dots_acl_body("n", "172.30.0.20", "2001:db8::/64", 80, text, sizeof(text)) < 0,
          "family mismatch rejected");
    check(ankah_dots_acl_body("n", "172.30.0.20", "172.30.0.11/32", 0, text, sizeof(text)) < 0,
          "port zero rejected");
    check(ankah_dots_acl_body("n", "172.30.0.20", "172.30.0.11/32", 80, text, 16) < 0,
          "short buffer rejected");

    check(ankah_dots_client_body("ankah-demo", text, sizeof(text)) > 0, "client body");
    check(strcmp(text, "{\"ietf-dots-data-channel:dots-client\":[{\"cuid\":\"ankah-demo\"}]}") == 0,
          "client body text");
    check(!ankah_dots_valid_cuid("a/b"), "slash cuid rejected");
    check(!ankah_dots_valid_cuid(""), "empty cuid rejected");

    check(ankah_dots_status("HTTP/1.1 201 Created\r\n", 22) == 201, "status 201");
    check(ankah_dots_status("HTTP/1.1 204\r\n", 14) == 204, "status without reason");
    check(ankah_dots_status("HTTP/1.1 20", 11) == -1, "short status");
    check(ankah_dots_status("SSH-2.0-x 200 ", 14) == -1, "not HTTP");

    {
        const char body[] =
            "{\"ietf-dots-data-channel:acls\":{\"acl\":[{\"name\" : \"ankah-172-30-0-20\","
            "\"aces\":{\"ace\":[{\"name\":\"block\"}]}},{\"name\":\"other\"},"
            "{\"name\":\"ankah-10-0-0-1\"},{\"name\":\"ankah-bad\\\"x\"}]}}";
        size_t n = ankah_dots_scan_names(body, sizeof(body) - 1, "ankah-", names, 4);
        check(n == 2, "scan finds two ankah names");
        check(strcmp(names[0], "ankah-172-30-0-20") == 0, "first scanned name");
        check(strcmp(names[1], "ankah-10-0-0-1") == 0, "second scanned name");
        n = ankah_dots_scan_names(body, sizeof(body) - 1, "ankah-", names, 1);
        check(n == 1, "scan respects max");
    }
    puts("dots_policy ok");
    return 0;
}
