#include "ankah/session.h"

#include <stdlib.h>
#include <string.h>

#define MAX_SESSIONS 4096
#define MAX_PENDING_BYTES (64U * 1024U * 1024U)

static ankah_session sessions[MAX_SESSIONS];
static size_t pending_bytes;

static void random_hex(char output[33]) {
    static const char hex[] = "0123456789abcdef";
    unsigned char bytes[16];
    size_t i;
    if (ankah_random(bytes, sizeof(bytes)) != 0) { output[0] = 0; return; }
    for (i = 0; i < sizeof(bytes); ++i) {
        output[i * 2] = hex[bytes[i] >> 4];
        output[i * 2 + 1] = hex[bytes[i] & 15];
    }
    output[32] = 0;
}

static void release_post(ankah_session *session) {
    if (!session->saved_request) return;
    pending_bytes -= session->body_size + sizeof(*session->saved_request);
    free(session->saved_request);
    free(session->body);
    session->saved_request = NULL;
    session->body = NULL;
    session->body_size = 0;
    session->received = 0;
    session->token[0] = 0;
}

void ankah_session_discard(ankah_session *session) {
    if (!session) return;
    release_post(session);
    memset(session, 0, sizeof(*session));
}

static void expire(ankah_session *session, uint64_t now) {
    if (!session->active) return;
    if ((!session->solved_until && now > session->issued + 300) ||
        (session->solved_until && now > session->solved_until)) {
        ankah_session_discard(session);
        return;
    }
    if (session->saved_request && session->solved_until && now > session->body_until)
        release_post(session);
}

ankah_session *ankah_session_find(const char *id, uint64_t now) {
    size_t i;
    if (!id || strlen(id) != 32) return NULL;
    for (i = 0; i < MAX_SESSIONS; ++i) {
        expire(&sessions[i], now);
        if (sessions[i].active && strcmp(sessions[i].id, id) == 0)
            return &sessions[i];
    }
    return NULL;
}

ankah_session *ankah_session_new(const unsigned char secret[ANKAH_SECRET_SIZE],
                                 const char *host, uint64_t now,
                                 const ankah_request *request, const char *peer_ip) {
    ankah_session *session = NULL;
    size_t i, body_size = 0;
    int is_post;
    if (!request || !host || !peer_ip) return NULL;
    is_post = strcmp(request->method, "POST") == 0;
    if (is_post) {
        body_size = request->content_length;
        if (body_size > ANKAH_POST_REPLAY_MAX ||
            body_size + sizeof(ankah_request) > MAX_PENDING_BYTES - pending_bytes)
            return NULL;
    }
    for (i = 0; i < MAX_SESSIONS; ++i) {
        expire(&sessions[i], now);
        if (!sessions[i].active) { session = &sessions[i]; break; }
    }
    if (!session) return NULL;
    memset(session, 0, sizeof(*session));
    random_hex(session->id);
    random_hex(session->token);
    if (!session->id[0] || !session->token[0] ||
        ankah_issue_challenge(secret, host, now, 18, session->challenge) != 0) return NULL;
    strcpy(session->target, request->target);
    strcpy(session->peer_ip, peer_ip);
    session->issued = now;
    session->is_post = is_post;
    if (is_post) {
        session->saved_request = malloc(sizeof(*session->saved_request));
        session->body = malloc(body_size ? body_size : 1);
        if (!session->saved_request || !session->body) {
            free(session->saved_request);
            free(session->body);
            memset(session, 0, sizeof(*session));
            return NULL;
        }
        *session->saved_request = *request;
        session->body_size = body_size;
        pending_bytes += body_size + sizeof(ankah_request);
    }
    session->active = 1;
    return session;
}

int ankah_session_append(ankah_session *session, const void *data, size_t size) {
    if (!session || !session->active || !session->saved_request ||
        size > session->body_size - session->received) return -1;
    if (size) memcpy(session->body + session->received, data, size);
    session->received += size;
    return session->received == session->body_size ? 1 : 0;
}

int ankah_session_solve(ankah_session *session, uint64_t now) {
    if (!session || !session->active || now > session->issued + 300) return -1;
    session->solved_until = now + 1800;
    session->body_until = now + 300;
    return 0;
}

int ankah_session_solved(const ankah_session *session, uint64_t now) {
    return session && session->active && session->solved_until >= now &&
           session->solved_until != 0;
}

int ankah_session_take_post(ankah_session *session, const char *token, uint64_t now,
                             ankah_request **request, unsigned char **body,
                             size_t *size) {
    if (!ankah_session_solved(session, now) || !session->saved_request ||
        now > session->body_until || session->received != session->body_size ||
        !token || strcmp(session->token, token) != 0) return -1;
    *request = session->saved_request;
    *body = session->body;
    *size = session->body_size;
    pending_bytes -= session->body_size + sizeof(*session->saved_request);
    session->saved_request = NULL;
    session->body = NULL;
    session->body_size = 0;
    session->token[0] = 0;
    return 0;
}

void ankah_session_count(uint64_t now, ankah_session_totals *out) {
    size_t i;
    memset(out, 0, sizeof(*out));
    out->capacity = MAX_SESSIONS;
    out->pending_capacity = MAX_PENDING_BYTES;
    for (i = 0; i < MAX_SESSIONS; ++i) {
        expire(&sessions[i], now);
        if (!sessions[i].active) continue;
        ++out->active;
        if (ankah_session_solved(&sessions[i], now)) ++out->solved;
        if (sessions[i].saved_request) ++out->saved_posts;
    }
    out->pending_bytes = pending_bytes;
}
