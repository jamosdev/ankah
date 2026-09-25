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
    char other_pass[ANKAH_PASS_TEXT_MAX], identity[ANKAH_CLIENT_ID_TEXT_SIZE];
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
    failures += check(ankah_check_pass_identity(secret, "example.test", 1500, pass,
                                                identity) == 0 && strlen(identity) == 32,
                      "pass identity");
    failures += check(ankah_issue_pass(secret, "example.test", 2000, other_pass) == 0 &&
                      strcmp(pass, other_pass) != 0, "passes have unique identities");
    failures += check(ankah_check_pass(secret, "example.test", 2001, pass) != 0, "pass expiry");
    failures += check(ankah_check_pass(secret, "other.test", 1500, pass) != 0, "pass host binding");
    {
        char legacy[ANKAH_PASS_TEXT_MAX] =
            "2000.c90384f11f33b8ed94d41fe6feb7f3a25386f26734c2b802040b2b20cbf84693";
        failures += check(ankah_check_pass(secret, "example.test", 1500, legacy) == 0,
                          "legacy pass remains valid");
        failures += check(ankah_check_pass_identity(secret, "example.test", 1500,
                                                    legacy, identity) != 0,
                          "legacy pass has no identity");
    }
    return failures ? 1 : 0;
}
