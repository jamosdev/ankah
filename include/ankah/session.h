#ifndef ANKAH_SESSION_H
#define ANKAH_SESSION_H

#include "ankah/http.h"
#include "ankah/pow.h"
#include <stddef.h>
#include <stdint.h>

#define ANKAH_POST_REPLAY_MAX (2U * 1024U * 1024U)

typedef struct {
    char id[33];
    char token[33];
    char challenge[ANKAH_CHALLENGE_TEXT_MAX];
    char target[ANKAH_MAX_TARGET];
    char peer_ip[64];
    uint64_t issued;
    uint64_t solved_until;
    uint64_t body_until;
    ankah_request *saved_request;
    unsigned char *body;
    size_t body_size;
    size_t received;
    int active;
    int is_post;
    int issued_with_proof;
} ankah_session;

typedef struct {
    size_t active, solved, saved_posts, pending_bytes;
    size_t capacity, pending_capacity;
} ankah_session_totals;

ankah_session *ankah_session_new(const unsigned char secret[ANKAH_SECRET_SIZE],
                                 const char *host, uint64_t now,
                                 const ankah_request *request, const char *peer_ip);
ankah_session *ankah_session_new_with_proof(const unsigned char secret[ANKAH_SECRET_SIZE],
                                            const char *host, uint64_t now,
                                            const ankah_request *request,
                                            const char *peer_ip, int proved);
ankah_session *ankah_session_find(const char *id, uint64_t now);
void ankah_session_discard(ankah_session *session);
int ankah_session_append(ankah_session *session, const void *data, size_t size);
int ankah_session_solve(ankah_session *session, uint64_t now);
int ankah_session_solved(const ankah_session *session, uint64_t now);
int ankah_session_take_post(ankah_session *session, const char *token, uint64_t now,
                             ankah_request **request, unsigned char **body,
                             size_t *size);
/* Expires stale sessions as a side effect, like ankah_session_find. */
void ankah_session_count(uint64_t now, ankah_session_totals *out);

#endif
