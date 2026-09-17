#include "ankah/pow.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check(int condition, const char *message) {
    if (!condition) fprintf(stderr, "FAIL: %s\n", message);
    return condition ? 0 : 1;
}

int main(void) {
    unsigned char secret[ANKAH_SECRET_SIZE];
    char challenge[ANKAH_CHALLENGE_TEXT_MAX];
    char pass[ANKAH_PASS_TEXT_MAX];
    uint64_t counter;
    int failures = 0;
    memset(secret, 0x53, sizeof(secret));
    failures += check(ankah_issue_challenge(secret, "example.test", 1000, 8, challenge) == 0,
                      "issue challenge");
    if (failures) return 1;
    for (counter = 0; counter < 10000; ++counter) {
        if (ankah_check_answer(secret, "example.test", 1000, challenge, counter) == 0) break;
    }
    failures += check(counter < 10000, "find an answer");
    failures += check(ankah_check_answer(secret, "other.test", 1000, challenge, counter) != 0,
                      "host binding");
    failures += check(ankah_check_answer(secret, "example.test", 1301, challenge, counter) != 0,
                      "challenge expiry");
    failures += check(ankah_issue_pass(secret, "example.test", 2000, pass) == 0, "issue pass");
    failures += check(ankah_check_pass(secret, "example.test", 1500, pass) == 0, "pass valid");
    failures += check(ankah_check_pass(secret, "example.test", 2001, pass) != 0, "pass expiry");
    failures += check(ankah_check_pass(secret, "other.test", 1500, pass) != 0, "pass host binding");
    return failures ? 1 : 0;
}
