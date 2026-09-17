#include "ankah/session.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    unsigned char secret[ANKAH_SECRET_SIZE] = {0};
    ankah_request request = {0};
    ankah_session *session;
    ankah_request *saved;
    unsigned char *body;
    size_t size;
    char id[33], token[33];
    const uint64_t now = 1700000000;

    strcpy(request.method, "POST");
    strcpy(request.target, "/upload?x=1");
    request.content_length = 4;
    session = ankah_session_new(secret, "localhost", now, &request, "127.0.0.1");
    assert(session);
    strcpy(id, session->id);
    strcpy(token, session->token);
    assert(ankah_session_append(session, "ab", 2) == 0);
    assert(ankah_session_append(session, "cd", 2) == 1);
    assert(ankah_session_solve(session, now + 1) == 0);
    assert(ankah_session_take_post(session, "wrong", now + 2,
                                   &saved, &body, &size) == -1);
    assert(ankah_session_take_post(session, token, now + 2,
                                   &saved, &body, &size) == 0);
    assert(size == 4 && memcmp(body, "abcd", 4) == 0);
    assert(strcmp(saved->target, "/upload?x=1") == 0);
    free(saved);
    free(body);
    assert(ankah_session_take_post(session, token, now + 2,
                                   &saved, &body, &size) == -1);
    assert(ankah_session_find(id, now + 1802) == NULL);

    session = ankah_session_new(secret, "localhost", now, &request, "127.0.0.1");
    assert(session);
    strcpy(id, session->id);
    assert(ankah_session_find(id, now + 301) == NULL);

    session = ankah_session_new(secret, "localhost", now, &request, "127.0.0.1");
    assert(session);
    strcpy(id, session->id);
    strcpy(token, session->token);
    assert(ankah_session_append(session, "abcd", 4) == 1);
    assert(ankah_session_solve(session, now + 1) == 0);
    assert(ankah_session_take_post(session, token, now + 302,
                                   &saved, &body, &size) == -1);
    assert(ankah_session_find(id, now + 302));
    assert(!ankah_session_find(id, now + 302)->saved_request);

    request.content_length = ANKAH_POST_REPLAY_MAX + 1;
    assert(!ankah_session_new(secret, "localhost", now, &request, "127.0.0.1"));
    return 0;
}
