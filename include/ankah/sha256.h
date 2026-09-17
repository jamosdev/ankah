#ifndef ANKAH_SHA256_H
#define ANKAH_SHA256_H

#include <mbedtls/sha256.h>
#include <mbedtls/version.h>

static inline int ankah_sha256(const unsigned char *input, size_t length,
                               unsigned char output[32]) {
#if MBEDTLS_VERSION_MAJOR >= 3
    return mbedtls_sha256(input, length, output, 0);
#else
    return mbedtls_sha256_ret(input, length, output, 0);
#endif
}

#endif
