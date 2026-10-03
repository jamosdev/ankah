#include "ankah/session.h"
#include "ankah/files.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    unsigned char secret[ANKAH_SECRET_SIZE] = {0};
    ankah_request request = {0};
    ankah_session *session;
    ankah_request *saved = NULL;
    unsigned char *body = NULL;
    ankah_post_payload *payload = NULL;
    size_t size = 0;
    char id[33], token[33];
    const uint64_t now = 1700000000;
    (void)size;

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
                                   &saved, &body, &size, &payload) == -1);
    assert(ankah_session_take_post(session, token, now + 2,
                                   &saved, &body, &size, &payload) == 0);
    assert(size == 4 && memcmp(body, "abcd", 4) == 0);
    assert(strcmp(saved->target, "/upload?x=1") == 0);
    ankah_post_payload_release(payload);
    assert(ankah_session_take_post(session, token, now + 2,
                                   &saved, &body, &size, &payload) == -1);
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
                                   &saved, &body, &size, &payload) == -1);
    assert(ankah_session_find(id, now + 302));
    assert(!ankah_session_find(id, now + 302)->saved_request);

    {
        ankah_session_totals totals;
        ankah_session_count(now + 2, &totals);
        assert(totals.active == 1 && totals.solved == 1 && totals.saved_posts == 0);
        assert(totals.pending_bytes == 0 && totals.capacity == 4096);
        session = ankah_session_new(secret, "localhost", now, &request, "127.0.0.1");
        assert(session);
        ankah_session_count(now + 2, &totals);
        assert(totals.active == 2 && totals.solved == 1 && totals.saved_posts == 1);
        assert(totals.pending_bytes == 4 + sizeof(ankah_request));
        ankah_session_count(now + 2000, &totals);
        assert(totals.active == 0 && totals.pending_bytes == 0);
    }

    request.content_length = ANKAH_POST_REPLAY_MAX + 1;
    assert(!ankah_session_new(secret, "localhost", now, &request, "127.0.0.1"));

    {
        const uint64_t issued = now + 3000;
        ankah_session *first = NULL, *second = NULL;
        char peer[64];
        unsigned int i;
        strcpy(request.method, "GET");
        strcpy(request.target, "/private");
        request.content_length = 0;
        for (i = 0; i < 64; ++i) {
            session = ankah_session_new(secret, "localhost", issued, &request, "client-a");
            assert(session);
            if (!first) first = session;
            else if (!second) second = session;
        }
        assert(!ankah_session_new(secret, "localhost", issued, &request, "client-a"));
        assert(ankah_session_solve(first, issued + 1) == 0);
        assert(ankah_session_new(secret, "localhost", issued, &request, "client-a"));
        for (i = 64; i < 3072; ++i) {
            snprintf(peer, sizeof(peer), "client-%u", i);
            assert(ankah_session_new(secret, "localhost", issued, &request, peer));
        }
        assert(!ankah_session_new(secret, "localhost", issued, &request, "extra"));
        assert(ankah_session_new_with_proof(secret, "localhost", issued,
                                            &request, "proved", 1));
        assert(ankah_session_solve(second, issued + 1) == 0);
        assert(ankah_session_new(secret, "localhost", issued, &request, "extra"));
    }
    {
        ankah_session_snapshot *snapshot;
        unsigned char *image;
        size_t image_size;
        uint64_t generation;
        const uint64_t issued = now + 100001;
        ankah_session_totals totals;
        FILE *journal;
        ankah_session_count(issued, &totals);
        strcpy(request.method, "POST");
        strcpy(request.target, "/restart");
        request.content_length = 4;
        session = ankah_session_new(secret, "localhost", issued, &request, "127.0.0.1");
        assert(session);
        strcpy(id, session->id);
        strcpy(token, session->token);
        assert(ankah_session_append(session, "data", 4) == 1);
        assert(ankah_session_solve(session, issued + 1) == 0);
        snapshot = ankah_session_snapshot_begin(issued + 1);
        assert(snapshot);
        ankah_session_discard(session);
        while ((size = (size_t)ankah_session_snapshot_step(snapshot, 1024)) == 0) {}
        assert(size == 1);
        image = ankah_session_snapshot_detach(snapshot, &image_size, &generation);
        assert(image && generation);
        ankah_session_snapshot_free(snapshot);
        assert(ankah_file_replace("ankah-session-test.tmp", "ankah-session-test.1",
                                  image, image_size) == 0);
        free(image);
        assert(ankah_session_restore("ankah-session-test", issued + 2) == 0);
        session = ankah_session_find(id, issued + 2);
        assert(session && session->saved_request &&
               memcmp(session->body, "data", 4) == 0);
        assert(ankah_session_reserve_post(session, token, issued + 2) == 0);
        assert(ankah_session_reserve_post(session, token, issued + 2) == -1);
        ankah_session_unreserve_post(session);
        journal = fopen("ankah-session-test.journal", "wb");
        assert(journal);
        assert(fprintf(journal, "%s\n", id) == 33);
        assert(fclose(journal) == 0);
        ankah_session_discard(session);
        assert(ankah_session_restore("ankah-session-test", issued + 2) == 0);
        session = ankah_session_find(id, issued + 2);
        assert(session && !session->saved_request);
        remove("ankah-session-test.1");
        remove("ankah-session-test.journal");
    }
    return 0;
}
