#include "rate.h"

#include <string.h>

int ankah_rate_allow(rate_limit *limit, const char *ip, uint64_t now,
                     double global_burst, double global_refill,
                     double client_burst, double client_refill) {
    rate_bucket *bucket = NULL, *oldest = &limit->clients[0];
    unsigned int i;
    if (!limit->global_last_ns) {
        limit->global_last_ns = now;
        limit->global_tokens = global_burst;
    }
    limit->global_tokens += (double)(now - limit->global_last_ns) /
                            1000000000.0 * global_refill;
    if (limit->global_tokens > global_burst) limit->global_tokens = global_burst;
    limit->global_last_ns = now;
    for (i = 0; i < RATE_BUCKETS; ++i) {
        if (strcmp(limit->clients[i].ip, ip) == 0) {
            bucket = &limit->clients[i];
            break;
        }
        if (limit->clients[i].last_ns < oldest->last_ns) oldest = &limit->clients[i];
    }
    if (!bucket) {
        bucket = oldest;
        strcpy(bucket->ip, ip);
        bucket->tokens = client_burst;
        bucket->last_ns = now;
    }
    bucket->tokens += (double)(now - bucket->last_ns) /
                      1000000000.0 * client_refill;
    if (bucket->tokens > client_burst) bucket->tokens = client_burst;
    bucket->last_ns = now;
    if (bucket->tokens < 1.0) return 1;
    if (limit->global_tokens < 1.0) return 2;
    limit->global_tokens -= 1.0;
    bucket->tokens -= 1.0;
    return 0;
}
