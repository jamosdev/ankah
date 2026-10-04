#ifndef ANKAH_SESSION_H
#define ANKAH_SESSION_H

#include "ankah/http.h"
#include "ankah/pow.h"
#include <stddef.h>
#include <stdint.h>

#define ANKAH_POST_REPLAY_MAX (2U * 1024U * 1024U)
#define ANKAH_SESSION_CAPACITY 4096U
#define ANKAH_SESSION_SNAPSHOT_MAX (128U * 1024U * 1024U)

typedef struct ankah_post_payload ankah_post_payload;
typedef struct ankah_session_snapshot ankah_session_snapshot;

typedef struct {
    char host[256];
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
    ankah_post_payload *payload;
    size_t body_size;
    size_t received;
    int active;
    int is_post;
    int issued_with_proof;
    int consumption_pending;
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
ankah_session *ankah_session_find_host(const char *id, uint64_t now, const char *host);
ankah_session *ankah_session_accept_solved(const char *id, uint64_t now,
                                            const char *target, int is_post, const char *host);
void ankah_session_discard(ankah_session *session);
int ankah_session_append(ankah_session *session, const void *data, size_t size);
int ankah_session_solve(ankah_session *session, uint64_t now);
int ankah_session_solved(const ankah_session *session, uint64_t now);
int ankah_session_take_post(ankah_session *session, const char *token, uint64_t now,
                             ankah_request **request, unsigned char **body,
                             size_t *size, ankah_post_payload **payload);
void ankah_post_payload_release(ankah_post_payload *payload);
void ankah_session_cancel_post(ankah_session *session);
int ankah_session_reserve_post(ankah_session *session, const char *token, uint64_t now);
void ankah_session_unreserve_post(ankah_session *session);
int ankah_session_changed(void);
void ankah_session_snapshot_retry(void);
ankah_session_snapshot *ankah_session_snapshot_begin(uint64_t now);
/* Returns 1 when complete, 0 when more steps are needed, -1 on error. */
int ankah_session_snapshot_step(ankah_session_snapshot *snapshot, size_t budget);
unsigned char *ankah_session_snapshot_detach(ankah_session_snapshot *snapshot,
                                              size_t *size, uint64_t *generation);
void ankah_session_snapshot_free(ankah_session_snapshot *snapshot);
/* Validates an image using the recovery rules and copies saved POST IDs. */
int ankah_session_snapshot_saved_ids(const unsigned char *data, size_t size,
                                     char ids[][33], size_t capacity,
                                     size_t *count);
void ankah_session_discard_saved_posts(void);
/* Returns -2 when the consumption journal is malformed or unreadable. */
int ankah_session_restore(const char *path, uint64_t now, const char *primary_host);
void ankah_session_each_solved(uint64_t now,
                               void (*visit)(const ankah_session *, void *), void *owner);
/* Expires stale sessions as a side effect, like ankah_session_find. */
void ankah_session_count(uint64_t now, ankah_session_totals *out);

#endif
