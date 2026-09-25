#ifndef ANKAH_POW_H
#define ANKAH_POW_H

#include <stddef.h>
#include <stdint.h>

#define ANKAH_SECRET_SIZE 32
#define ANKAH_NONCE_SIZE 16
#define ANKAH_CLIENT_ID_SIZE 16
#define ANKAH_CLIENT_ID_TEXT_SIZE (ANKAH_CLIENT_ID_SIZE * 2 + 1)
#define ANKAH_MAC_SIZE 32
#define ANKAH_CHALLENGE_TEXT_MAX 160
#define ANKAH_PASS_TEXT_MAX 160

/* All text fields use lowercase hex and ASCII decimal. A zero result means OK. */
int ankah_random(unsigned char *out, size_t size);
int ankah_issue_challenge(const unsigned char secret[ANKAH_SECRET_SIZE],
                          const char *host, uint64_t now, unsigned int bits,
                          char out[ANKAH_CHALLENGE_TEXT_MAX]);
int ankah_check_answer(const unsigned char secret[ANKAH_SECRET_SIZE],
                       const char *host, uint64_t now, const char *challenge,
                       uint64_t counter);
int ankah_issue_pass(const unsigned char secret[ANKAH_SECRET_SIZE],
                     const char *host, uint64_t expiry,
                     char out[ANKAH_PASS_TEXT_MAX]);
int ankah_check_pass(const unsigned char secret[ANKAH_SECRET_SIZE],
                     const char *host, uint64_t now, const char *pass);
/* Accepts only uniquely identified version 2 passes and copies their client ID. */
int ankah_check_pass_identity(const unsigned char secret[ANKAH_SECRET_SIZE],
                              const char *host, uint64_t now, const char *pass,
                              char out[ANKAH_CLIENT_ID_TEXT_SIZE]);

#endif
