#include "abuse_policy.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define S UINT64_C(1000000000)
int main(void) {
    ankah_abuse_policy *policy = ankah_abuse_create();
    unsigned int i;
    char ip[64], path[64];
    assert(policy);
    ankah_abuse_set_profile(policy, ANKAH_ABUSE_CONSERVATIVE);
    for (i = 0; i < 7; ++i)
        assert(!ankah_abuse_record(policy, "192.0.2.1", ANKAH_ABUSE_INVALID_PROOF, NULL, i * S));
    assert(ankah_abuse_record(policy, "192.0.2.1", ANKAH_ABUSE_INVALID_PROOF, NULL, 7 * S));
    assert(!ankah_abuse_record(policy, "192.0.2.1", ANKAH_ABUSE_INVALID_PROOF, NULL, 8 * S));
    assert(!ankah_abuse_record(policy, "192.0.2.2", ANKAH_ABUSE_INVALID_PROOF, NULL, 8 * S));
    for (i = 0; i < 39; ++i) {
        snprintf(path, sizeof(path), "/scan/%u?ignored=%u", i, i);
        assert(!ankah_abuse_record(policy, "192.0.2.3", ANKAH_ABUSE_SCAN, path, i * S / 2));
    }
    assert(ankah_abuse_record(policy, "192.0.2.3", ANKAH_ABUSE_SCAN, "/scan/39", 20 * S));
    for (i = 0; i < 4096 + 1; ++i) {
        snprintf(ip, sizeof(ip), "2001:db8::%x", i);
        ankah_abuse_record(policy, ip, ANKAH_ABUSE_BODY_STALL, NULL, (100 + i) * S);
    }
    assert(!ankah_abuse_record(policy, "192.0.2.1", ANKAH_ABUSE_INVALID_PROOF, NULL, 5000 * S));
    ankah_abuse_destroy(policy);
    policy = ankah_abuse_create();
    assert(policy);
    ankah_abuse_set_profile(policy, ANKAH_ABUSE_STRICT);
    for (i = 0; i < 3; ++i)
        assert(!ankah_abuse_record(policy, "192.0.2.4", ANKAH_ABUSE_CLIENT_RATE, NULL, i * S));
    assert(ankah_abuse_record(policy, "192.0.2.4", ANKAH_ABUSE_CLIENT_RATE, NULL, 3 * S));
    ankah_abuse_destroy(policy);
    policy = ankah_abuse_create();
    assert(policy);
    ankah_abuse_set_profile(policy, ANKAH_ABUSE_STRICT);
    for (i = 0; i < 20; ++i) {
        snprintf(path, sizeof(path), "/same?q=%u", i);
        assert(!ankah_abuse_record(policy, "192.0.2.6", ANKAH_ABUSE_SCAN, path, i * S / 10));
    }
    assert(!ankah_abuse_record(policy, "192.0.2.7", ANKAH_ABUSE_INVALID_PROOF, NULL, 0));
    assert(!ankah_abuse_record(policy, "192.0.2.7", ANKAH_ABUSE_INVALID_PROOF, NULL, 30 * S));
    assert(!ankah_abuse_record(policy, "192.0.2.7", ANKAH_ABUSE_INVALID_PROOF, NULL, 59 * S));
    assert(!ankah_abuse_record(policy, "192.0.2.7", ANKAH_ABUSE_INVALID_PROOF, NULL, 60 * S));
    assert(ankah_abuse_record(policy, "192.0.2.7", ANKAH_ABUSE_INVALID_PROOF, NULL, 61 * S));
    assert(!ankah_abuse_record(policy, "192.0.2.8", ANKAH_ABUSE_BODY_STALL, NULL, 0));
    assert(ankah_abuse_record(policy, "192.0.2.8", ANKAH_ABUSE_BODY_STALL, NULL, S));
    assert(!ankah_abuse_record(policy, "192.0.2.8", ANKAH_ABUSE_BODY_STALL, NULL, 2 * S));
    assert(ankah_abuse_record(policy, "192.0.2.8", ANKAH_ABUSE_BODY_STALL, NULL, 61 * S));
    ankah_abuse_destroy(policy);
    policy = ankah_abuse_create();
    assert(policy);
    ankah_abuse_set_profile(policy, ANKAH_ABUSE_OFF);
    for (i = 0; i < 100; ++i)
        assert(!ankah_abuse_record(policy, "192.0.2.5", ANKAH_ABUSE_CLIENT_RATE, NULL, i * S));
    ankah_abuse_destroy(policy);
    return 0;
}
