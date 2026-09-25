#include "rate.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>

static rate_limit anonymous_limit, protected_limit, client_limit;

int main(void) {
    const uint64_t now = UINT64_C(1000000000);
    char peer[64];
    unsigned int i;

    for (i = 0; i < 200; ++i) {
        snprintf(peer, sizeof(peer), "anonymous-%u", i / 40);
        assert(ankah_rate_allow(&anonymous_limit, peer, now, 200, 100, 40, 20) == 0);
    }
    assert(ankah_rate_allow(&anonymous_limit, "new", now, 200, 100, 40, 20) == 2);
    assert(ankah_rate_allow(&protected_limit, "proved", now,
                            1000, 500, 200, 100) == 0);
    assert(ankah_rate_allow(&anonymous_limit, "new", now + UINT64_C(10000000),
                            200, 100, 40, 20) == 0);
    assert(ankah_rate_allow(&anonymous_limit, "new", now + UINT64_C(10000000),
                            200, 100, 40, 20) == 2);

    for (i = 0; i < 40; ++i)
        assert(ankah_rate_allow(&client_limit, "one", now, 200, 100, 40, 20) == 0);
    assert(ankah_rate_allow(&client_limit, "one", now, 200, 100, 40, 20) == 1);
    assert(client_limit.global_tokens == 160.0);
    assert(ankah_rate_allow(&client_limit, "one", now + UINT64_C(50000000),
                            200, 100, 40, 20) == 0);
    assert(ankah_rate_allow(&client_limit, "one", now + UINT64_C(50000000),
                            200, 100, 40, 20) == 1);

    for (i = 0; i < 999; ++i) {
        snprintf(peer, sizeof(peer), "protected-%u", i / 200);
        assert(ankah_rate_allow(&protected_limit, peer, now,
                                1000, 500, 200, 100) == 0);
    }
    assert(ankah_rate_allow(&protected_limit, "extra", now,
                            1000, 500, 200, 100) == 2);
    assert(ankah_rate_allow(&protected_limit, "extra", now + UINT64_C(2000000),
                            1000, 500, 200, 100) == 0);
    return 0;
}
