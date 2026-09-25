#ifndef ANKAH_RATE_H
#define ANKAH_RATE_H

#include <stdint.h>

#define RATE_BUCKETS 1024

typedef struct {
    char ip[64];
    double tokens;
    uint64_t last_ns;
} rate_bucket;

typedef struct {
    rate_bucket clients[RATE_BUCKETS];
    double global_tokens;
    uint64_t global_last_ns;
} rate_limit;

/* 0 admits, 1 rejects by the client bucket, 2 rejects by the global bucket. */
int ankah_rate_allow(rate_limit *limit, const char *ip, uint64_t now,
                     double global_burst, double global_refill,
                     double client_burst, double client_refill);

#endif
