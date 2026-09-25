#include "ankah/pow.h"

#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include "ankah/sha256.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hex_encode(const unsigned char *in, size_t count, char *out) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < count; ++i) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[count * 2] = 0;
}

static int lower_hex(const char *value, size_t count) {
    size_t i;
    for (i = 0; i < count; ++i) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return -1;
    }
    return value[count] == 0 ? 0 : -1;
}

static int equal_secret(const char *a, const char *b, size_t count) {
    unsigned int difference = 0;
    size_t i;
    for (i = 0; i < count; ++i) difference |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return difference == 0;
}

static int decimal_u64(const char *value, uint64_t *out) {
    uint64_t result = 0;
    size_t i;
    if (value[0] == 0 || (value[0] == '0' && value[1] != 0)) return -1;
    for (i = 0; value[i]; ++i) {
        unsigned int digit;
        if (value[i] < '0' || value[i] > '9') return -1;
        digit = (unsigned int)(value[i] - '0');
        if (result > (UINT64_MAX - digit) / 10) return -1;
        result = result * 10 + digit;
    }
    *out = result;
    return 0;
}

static int mac(const unsigned char secret[ANKAH_SECRET_SIZE],
               const char *kind, const char *host, const char *fields,
               char out[ANKAH_MAC_SIZE * 2 + 1]) {
    char message[512];
    unsigned char digest[ANKAH_MAC_SIZE];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int length;
    if (!host || strlen(host) > 253 || !info) return -1;
    length = snprintf(message, sizeof(message), "%s|%s|%s", kind, host, fields);
    if (length < 0 || (size_t)length >= sizeof(message)) return -1;
    if (mbedtls_md_hmac(info, secret, ANKAH_SECRET_SIZE,
                        (const unsigned char *)message, (size_t)length, digest) != 0) return -1;
    hex_encode(digest, sizeof(digest), out);
    return 0;
}

int ankah_random(unsigned char *out, size_t size) {
    mbedtls_entropy_context entropy;
    int result;
    if (!out || size == 0) return -1;
    mbedtls_entropy_init(&entropy);
    result = mbedtls_entropy_func(&entropy, out, size);
    mbedtls_entropy_free(&entropy);
    return result == 0 ? 0 : -1;
}

int ankah_issue_challenge(const unsigned char secret[ANKAH_SECRET_SIZE],
                          const char *host, uint64_t now, unsigned int bits,
                          char out[ANKAH_CHALLENGE_TEXT_MAX]) {
    unsigned char nonce[ANKAH_NONCE_SIZE];
    char nonce_hex[ANKAH_NONCE_SIZE * 2 + 1];
    char fields[80];
    char signature[ANKAH_MAC_SIZE * 2 + 1];
    int length;
    if (!secret || !out || bits < 8 || bits > 24) return -1;
    if (ankah_random(nonce, sizeof(nonce)) != 0) return -1;
    hex_encode(nonce, sizeof(nonce), nonce_hex);
    length = snprintf(fields, sizeof(fields), "%s.%" PRIu64 ".%u", nonce_hex, now, bits);
    if (length < 0 || (size_t)length >= sizeof(fields)) return -1;
    if (mac(secret, "challenge", host, fields, signature) != 0) return -1;
    length = snprintf(out, ANKAH_CHALLENGE_TEXT_MAX, "%s.%s", fields, signature);
    return length > 0 && length < ANKAH_CHALLENGE_TEXT_MAX ? 0 : -1;
}

int ankah_check_answer(const unsigned char secret[ANKAH_SECRET_SIZE],
                       const char *host, uint64_t now, const char *challenge,
                       uint64_t counter) {
    char copy[ANKAH_CHALLENGE_TEXT_MAX];
    char *nonce, *timestamp, *difficulty, *signature;
    char *dot;
    char fields[80], expected[ANKAH_MAC_SIZE * 2 + 1], candidate[96];
    uint64_t issued, bit_count;
    unsigned char digest[32];
    unsigned int full_bytes, remaining, i;
    int length;
    if (!secret || !challenge || strlen(challenge) >= sizeof(copy)) return -1;
    strcpy(copy, challenge);
    nonce = copy;
    dot = strchr(nonce, '.'); if (!dot) return -1; *dot = 0;
    timestamp = dot + 1;
    dot = strchr(timestamp, '.'); if (!dot) return -1; *dot = 0;
    difficulty = dot + 1;
    dot = strchr(difficulty, '.'); if (!dot) return -1; *dot = 0;
    signature = dot + 1;
    if (strlen(nonce) != ANKAH_NONCE_SIZE * 2 || lower_hex(nonce, ANKAH_NONCE_SIZE * 2) != 0 ||
        strlen(signature) != ANKAH_MAC_SIZE * 2 || lower_hex(signature, ANKAH_MAC_SIZE * 2) != 0 ||
        decimal_u64(timestamp, &issued) != 0 || decimal_u64(difficulty, &bit_count) != 0 ||
        bit_count < 8 || bit_count > 24 || issued > now + 30 || now > issued + 300) return -1;
    length = snprintf(fields, sizeof(fields), "%s.%s.%s", nonce, timestamp, difficulty);
    if (length < 0 || (size_t)length >= sizeof(fields) ||
        mac(secret, "challenge", host, fields, expected) != 0 ||
        !equal_secret(signature, expected, ANKAH_MAC_SIZE * 2)) return -1;
    length = snprintf(candidate, sizeof(candidate), "%s:%" PRIu64, nonce, counter);
    if (length < 0 || (size_t)length >= sizeof(candidate) ||
        ankah_sha256((const unsigned char *)candidate, (size_t)length, digest) != 0) return -1;
    full_bytes = (unsigned int)(bit_count / 8);
    remaining = (unsigned int)(bit_count % 8);
    for (i = 0; i < full_bytes; ++i) if (digest[i] != 0) return -1;
    if (remaining && (digest[full_bytes] >> (8 - remaining)) != 0) return -1;
    return 0;
}

int ankah_issue_pass(const unsigned char secret[ANKAH_SECRET_SIZE],
                     const char *host, uint64_t expiry,
                     char out[ANKAH_PASS_TEXT_MAX]) {
    unsigned char client_id[ANKAH_CLIENT_ID_SIZE];
    char client_id_hex[ANKAH_CLIENT_ID_TEXT_SIZE];
    char fields[96], signature[ANKAH_MAC_SIZE * 2 + 1];
    int length;
    if (!secret || !out) return -1;
    if (ankah_random(client_id, sizeof(client_id)) != 0) return -1;
    hex_encode(client_id, sizeof(client_id), client_id_hex);
    length = snprintf(fields, sizeof(fields), "2.%s.%" PRIu64,
                      client_id_hex, expiry);
    if (length < 0 || (size_t)length >= sizeof(fields) ||
        mac(secret, "pass", host, fields, signature) != 0) return -1;
    length = snprintf(out, ANKAH_PASS_TEXT_MAX, "%s.%s", fields, signature);
    return length > 0 && length < ANKAH_PASS_TEXT_MAX ? 0 : -1;
}

static int check_legacy_pass(const unsigned char secret[ANKAH_SECRET_SIZE],
                             const char *host, uint64_t now, const char *pass) {
    char copy[ANKAH_PASS_TEXT_MAX], expected[ANKAH_MAC_SIZE * 2 + 1];
    char *signature;
    uint64_t expiry;
    if (!secret || !pass || strlen(pass) >= sizeof(copy)) return -1;
    strcpy(copy, pass);
    signature = strchr(copy, '.');
    if (!signature) return -1;
    *signature++ = 0;
    if (decimal_u64(copy, &expiry) != 0 || expiry < now || expiry > now + 86400 ||
        strlen(signature) != ANKAH_MAC_SIZE * 2 || lower_hex(signature, ANKAH_MAC_SIZE * 2) != 0 ||
        mac(secret, "pass", host, copy, expected) != 0) return -1;
    return equal_secret(signature, expected, ANKAH_MAC_SIZE * 2) ? 0 : -1;
}

int ankah_check_pass_identity(const unsigned char secret[ANKAH_SECRET_SIZE],
                              const char *host, uint64_t now, const char *pass,
                              char out[ANKAH_CLIENT_ID_TEXT_SIZE]) {
    char copy[ANKAH_PASS_TEXT_MAX], fields[96];
    char expected[ANKAH_MAC_SIZE * 2 + 1];
    char *client_id, *timestamp, *signature, *dot;
    uint64_t expiry;
    int length;
    if (!secret || !pass || !out || strlen(pass) >= sizeof(copy)) return -1;
    strcpy(copy, pass);
    dot = strchr(copy, '.');
    if (!dot) return -1;
    *dot++ = 0;
    if (strcmp(copy, "2") != 0) return -1;
    client_id = dot;
    dot = strchr(client_id, '.');
    if (!dot) return -1;
    *dot++ = 0;
    timestamp = dot;
    dot = strchr(timestamp, '.');
    if (!dot) return -1;
    *dot++ = 0;
    signature = dot;
    if (strlen(client_id) != ANKAH_CLIENT_ID_SIZE * 2 ||
        lower_hex(client_id, ANKAH_CLIENT_ID_SIZE * 2) != 0 ||
        decimal_u64(timestamp, &expiry) != 0 || expiry < now || expiry > now + 86400 ||
        strlen(signature) != ANKAH_MAC_SIZE * 2 ||
        lower_hex(signature, ANKAH_MAC_SIZE * 2) != 0) return -1;
    length = snprintf(fields, sizeof(fields), "2.%s.%s", client_id, timestamp);
    if (length < 0 || (size_t)length >= sizeof(fields) ||
        mac(secret, "pass", host, fields, expected) != 0 ||
        !equal_secret(signature, expected, ANKAH_MAC_SIZE * 2)) return -1;
    memcpy(out, client_id, ANKAH_CLIENT_ID_TEXT_SIZE);
    return 0;
}

int ankah_check_pass(const unsigned char secret[ANKAH_SECRET_SIZE],
                     const char *host, uint64_t now, const char *pass) {
    char identity[ANKAH_CLIENT_ID_TEXT_SIZE];
    if (ankah_check_pass_identity(secret, host, now, pass, identity) == 0) return 0;
    return check_legacy_pass(secret, host, now, pass);
}
