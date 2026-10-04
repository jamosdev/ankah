#include "ankah/files.h"
#include "ankah/session.h"
#include "disk_writer.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uv_loop_t loop;
static unsigned int completed;
static int last_kind, last_result;
static unsigned int kind_completed[6];
static int kind_result[6];
static unsigned int kind_order[6];
static ankah_session *callback_consume_session;
static char callback_consume_token[33];

static void result_callback(int kind, void *context, int result,
                            uint64_t generation, void *owner) {
    (void)context;
    (void)generation;
    (void)owner;
    last_kind = kind;
    last_result = result;
    assert(kind > 0 && kind < 6);
    kind_result[kind] = result;
    kind_order[kind] = completed + 1;
    ++kind_completed[kind];
    if (kind == ANKAH_DISK_CONSUME && callback_consume_session) {
        ankah_request *request = NULL;
        unsigned char *body = NULL;
        ankah_post_payload *payload = NULL;
        size_t size = 0;
        assert(result == 0);
        assert(ankah_session_take_post(callback_consume_session,
                                       callback_consume_token, (uint64_t)time(NULL),
                                       &request, &body, &size, &payload) == 0);
        ankah_post_payload_release(payload);
    }
    if (kind == ANKAH_DISK_SESSIONS) ankah_disk_session_result_done();
    ++completed;
}

static int wait_result(int kind) {
    unsigned int before = completed;
    while (completed == before) assert(uv_run(&loop, UV_RUN_ONCE) != 0);
    assert(last_kind == kind);
    return last_result;
}

static int wait_kind(int kind, unsigned int before) {
    while (kind_completed[kind] == before)
        assert(uv_run(&loop, UV_RUN_ONCE) != 0);
    return kind_result[kind];
}

static void start_writer(const char *path) {
    assert(uv_loop_init(&loop) == 0);
    assert(ankah_disk_start(&loop, result_callback, NULL, path) == 0);
}

static void stop_writer(void) {
    ankah_disk_stop();
    uv_run(&loop, UV_RUN_DEFAULT);
    ankah_disk_join();
    assert(uv_loop_close(&loop) == 0);
}

static void name(char *out, size_t size, const char *base, const char *suffix) {
    int written = snprintf(out, size, "%s%s", base, suffix);
    assert(written > 0 && (size_t)written < size);
}

static size_t journal_size(const char *base) {
    char path[560];
    struct stat metadata;
    name(path, sizeof(path), base, ".journal");
    if (stat(path, &metadata) != 0) return 0;
    return (size_t)metadata.st_size;
}

static ankah_session *new_post(char id[33], char token[33], uint64_t now) {
    unsigned char secret[ANKAH_SECRET_SIZE] = {0};
    ankah_request request = {0};
    ankah_session *session;
    strcpy(request.method, "POST");
    strcpy(request.target, "/submit");
    request.content_length = 4;
    session = ankah_session_new(secret, "example.test", now,
                                &request, "127.0.0.1");
    assert(session);
    strcpy(id, session->id);
    strcpy(token, session->token);
    assert(ankah_session_append(session, "body", 4) == 1);
    assert(ankah_session_solve(session, now) == 0);
    return session;
}

static unsigned char *make_snapshot(size_t *size, uint64_t *generation,
                                    uint64_t now) {
    ankah_session_snapshot *snapshot = ankah_session_snapshot_begin(now);
    unsigned char *image;
    int result;
    assert(snapshot);
    do result = ankah_session_snapshot_step(snapshot, 256U * 1024U);
    while (result == 0);
    assert(result == 1);
    image = ankah_session_snapshot_detach(snapshot, size, generation);
    assert(image);
    ankah_session_snapshot_free(snapshot);
    return image;
}

static void write_initial_slots(const char *base, uint64_t now) {
    char temp[560], target[560];
    unsigned char *image;
    size_t size;
    uint64_t generation;
    image = make_snapshot(&size, &generation, now);
    name(temp, sizeof(temp), base, ".tmp");
    name(target, sizeof(target), base, ".0");
    assert(ankah_file_replace(temp, target, image, size) == 0);
    name(target, sizeof(target), base, ".1");
    assert(ankah_file_replace(temp, target, image, size) == 0);
    free(image);
}

static int queue_snapshot(const char *base, uint64_t now) {
    unsigned char *image;
    size_t size;
    uint64_t generation;
    assert(ankah_disk_session_capture_begin() == 0);
    image = make_snapshot(&size, &generation, now);
    assert(ankah_disk_snapshot(ANKAH_DISK_SESSIONS, base,
                               image, size, generation) == 0);
    return wait_result(ANKAH_DISK_SESSIONS);
}

static int consume(const char *base, ankah_session *session,
                   const char *id, const char *token, uint64_t now) {
    ankah_request *request = NULL;
    unsigned char *body = NULL;
    ankah_post_payload *payload = NULL;
    size_t size = 0;
    int result;
    assert(ankah_session_reserve_post(session, token, now) == 0);
    assert(ankah_disk_consume(base, id, NULL) == 0);
    result = wait_result(ANKAH_DISK_CONSUME);
    if (result == 0) {
        assert(ankah_session_take_post(session, token, now,
                                       &request, &body, &size, &payload) == 0);
        ankah_post_payload_release(payload);
    } else ankah_session_unreserve_post(session);
    return result;
}

static void test_building(const char *base, uint64_t now) {
    char id[33], token[33];
    ankah_session *session = new_post(id, token, now);
    ankah_session_snapshot *building;
    unsigned char *image;
    size_t size;
    uint64_t generation;
    int result;
    write_initial_slots(base, now);
    start_writer(base);
    assert(ankah_disk_session_capture_begin() == 0);
    building = ankah_session_snapshot_begin(now);
    assert(building);
    assert(consume(base, session, id, token, now) == 0);
    assert(ankah_disk_maintain() == 0);
    assert(wait_result(ANKAH_DISK_MAINTAIN) != 0);
    assert(journal_size(base) == 33);
    do result = ankah_session_snapshot_step(building, 256U * 1024U);
    while (result == 0);
    assert(result == 1);
    image = ankah_session_snapshot_detach(building, &size, &generation);
    assert(image);
    ankah_session_snapshot_free(building);
    assert(ankah_disk_snapshot(ANKAH_DISK_SESSIONS, base,
                               image, size, generation) == 0);
    assert(wait_result(ANKAH_DISK_SESSIONS) == 0);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 0);
    stop_writer();
    ankah_session_discard(session);
}

static void test_queued(const char *base, uint64_t now) {
    char id[33], token[33], journal[560];
    ankah_session *session = new_post(id, token, now);
    FILE *file;
    unsigned char *image;
    size_t size;
    uint64_t generation;
    unsigned int before_maintain, before_consume, before_snapshot;
    ankah_request *saved = NULL;
    unsigned char *body = NULL;
    ankah_post_payload *payload = NULL;
    write_initial_slots(base, now);
    name(journal, sizeof(journal), base, ".journal");
    file = fopen(journal, "wb");
    assert(file);
    assert(fprintf(file, "%s\n", id) == 33);
    assert(fclose(file) == 0);
    start_writer(base);
    ankah_disk_test_pause_maintenance();
    before_maintain = kind_completed[ANKAH_DISK_MAINTAIN];
    assert(ankah_disk_maintain() == 0);
    ankah_disk_test_wait_maintenance();
    assert(ankah_disk_session_capture_begin() == 0);
    image = make_snapshot(&size, &generation, now);
    before_snapshot = kind_completed[ANKAH_DISK_SESSIONS];
    assert(ankah_disk_snapshot(ANKAH_DISK_SESSIONS, base,
                               image, size, generation) == 0);
    assert(ankah_session_reserve_post(session, token, now) == 0);
    before_consume = kind_completed[ANKAH_DISK_CONSUME];
    assert(ankah_disk_consume(base, id, NULL) == 0);
    ankah_disk_test_resume_maintenance();
    assert(wait_kind(ANKAH_DISK_MAINTAIN, before_maintain) != 0);
    assert(wait_kind(ANKAH_DISK_CONSUME, before_consume) == 0);
    assert(wait_kind(ANKAH_DISK_SESSIONS, before_snapshot) == 0);
    assert(ankah_session_take_post(session, token, now,
                                   &saved, &body, &size, &payload) == 0);
    ankah_post_payload_release(payload);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 0);
    stop_writer();
    ankah_session_discard(session);
}

static void test_pending_callback(const char *base, uint64_t now) {
    char id[33], token[33], journal[560];
    ankah_session *session = new_post(id, token, now);
    FILE *file;
    unsigned char *image;
    size_t size;
    size_t saved_count;
    char saved_ids[1][33];
    uint64_t generation;
    size_t i;
    unsigned int before_consume, before_maintain, before_snapshot;
    name(journal, sizeof(journal), base, ".journal");
    file = fopen(journal, "wb");
    assert(file);
    for (i = 0; i < ANKAH_JOURNAL_LIMIT / 33U - 1; ++i)
        assert(fprintf(file, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n") == 33);
    assert(fclose(file) == 0);
    start_writer(base);
    before_consume = kind_completed[ANKAH_DISK_CONSUME];
    before_maintain = kind_completed[ANKAH_DISK_MAINTAIN];
    before_snapshot = kind_completed[ANKAH_DISK_SESSIONS];
    assert(ankah_session_reserve_post(session, token, now) == 0);
    assert(ankah_disk_consume(base, id, NULL) == 0);
    ankah_disk_test_wait_pending_results(1);
    assert(journal_size(base) == 33U * (ANKAH_JOURNAL_LIMIT / 33U));
    assert(ankah_disk_maintain() == 0);
    ankah_disk_test_wait_pending_results(2);
    assert(journal_size(base) == 33);
    assert(ankah_disk_session_capture_begin() == 0);
    image = make_snapshot(&size, &generation, now);
    assert(ankah_session_snapshot_saved_ids(image, size, saved_ids, 1,
                                             &saved_count) == 0);
    assert(saved_count == 1 && strcmp(saved_ids[0], id) == 0);
    assert(ankah_disk_snapshot(ANKAH_DISK_SESSIONS, base,
                               image, size, generation) == 0);
    ankah_disk_test_wait_pending_results(3);
    assert(journal_size(base) == 33);
    callback_consume_session = session;
    strcpy(callback_consume_token, token);
    assert(wait_kind(ANKAH_DISK_CONSUME, before_consume) == 0);
    assert(wait_kind(ANKAH_DISK_MAINTAIN, before_maintain) == 0);
    assert(kind_completed[ANKAH_DISK_SESSIONS] > before_snapshot);
    assert(kind_result[ANKAH_DISK_SESSIONS] == 0);
    callback_consume_session = NULL;
    assert(!session->saved_request);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 0);
    stop_writer();
    ankah_session_discard(session);
}

static void test_snapshot_priority(const char *base, uint64_t now) {
    char id[33], token[33], journal[560];
    ankah_session *session = new_post(id, token, now);
    ankah_request *request = NULL;
    unsigned char *body = NULL, *image;
    ankah_post_payload *payload = NULL;
    FILE *file;
    size_t i, size = 0;
    uint64_t generation;
    unsigned int before_maintain, before_consume, before_snapshot;
    name(journal, sizeof(journal), base, ".journal");
    file = fopen(journal, "wb");
    assert(file);
    for (i = 0; i < ANKAH_JOURNAL_LIMIT / 33U - 1; ++i)
        assert(fprintf(file, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n") == 33);
    assert(fclose(file) == 0);
    start_writer(base);
    ankah_disk_test_pause_maintenance();
    before_maintain = kind_completed[ANKAH_DISK_MAINTAIN];
    before_consume = kind_completed[ANKAH_DISK_CONSUME];
    before_snapshot = kind_completed[ANKAH_DISK_SESSIONS];
    assert(ankah_disk_maintain() == 0);
    ankah_disk_test_wait_maintenance();
    assert(ankah_session_reserve_post(session, token, now) == 0);
    assert(ankah_disk_consume(base, id, NULL) == 0);
    assert(ankah_disk_session_capture_begin() == 0);
    image = make_snapshot(&size, &generation, now);
    assert(ankah_disk_snapshot(ANKAH_DISK_SESSIONS, base,
                               image, size, generation) == 0);
    ankah_disk_test_resume_maintenance();
    assert(wait_kind(ANKAH_DISK_MAINTAIN, before_maintain) != 0);
    assert(wait_kind(ANKAH_DISK_SESSIONS, before_snapshot) == 0);
    assert(wait_kind(ANKAH_DISK_CONSUME, before_consume) == 0);
    assert(kind_order[ANKAH_DISK_SESSIONS] < kind_order[ANKAH_DISK_CONSUME]);
    assert(ankah_session_take_post(session, token, now,
                                   &request, &body, &size, &payload) == 0);
    ankah_post_payload_release(payload);
    stop_writer();
    ankah_session_discard(session);
}

static void test_snapshot_sync_failure(const char *base, uint64_t now) {
    char id[33], token[33];
    ankah_session *session = new_post(id, token, now);
    write_initial_slots(base, now);
    start_writer(base);
    assert(consume(base, session, id, token, now) == 0);
    ankah_file_test_fail_parent_sync_once(".0");
    assert(queue_snapshot(base, now) != 0);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 0);
    stop_writer();
    ankah_session_discard(session);
}

static void test_journal_sync_failure(const char *base, uint64_t now) {
    char id_a[33], token_a[33], id_b[33], token_b[33], journal[560];
    ankah_session *a = new_post(id_a, token_a, now);
    ankah_session *b;
    FILE *file;
    write_initial_slots(base, now);
    start_writer(base);
    assert(consume(base, a, id_a, token_a, now) == 0);
    b = new_post(id_b, token_b, now);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 33);
    ankah_file_test_fail_parent_sync_once(".journal");
    assert(queue_snapshot(base, now) == 0);
    assert(consume(base, b, id_b, token_b, now) != 0);
    stop_writer();
    name(journal, sizeof(journal), base, ".journal");
    file = fopen(journal, "wb");
    assert(file);
    assert(fprintf(file, "%s\n", id_a) == 33);
    assert(fclose(file) == 0);
    assert(ankah_session_restore(base, now, "example.test") == 0);
    assert(ankah_session_find(id_b, now)->saved_request != NULL);
    assert(ankah_session_find(id_a, now)->saved_request == NULL);
    ankah_session_discard(a);
    ankah_session_discard(b);
}

static void test_malformed_repair(const char *base, uint64_t now) {
    char id[33], token[33], journal[560];
    ankah_session *session = new_post(id, token, now);
    ankah_disk_session_state state;
    FILE *file;
    unsigned int attempts;
    write_initial_slots(base, now);
    name(journal, sizeof(journal), base, ".journal");
    file = fopen(journal, "wb");
    assert(file);
    assert(fwrite("x", 1, 1, file) == 1);
    assert(fclose(file) == 0);
    assert(ankah_session_restore(base, now, "example.test") == -2);
    assert(!ankah_session_find(id, now)->saved_request);
    start_writer(base);
    ankah_disk_session_state_get(&state);
    assert(state.journal_bad);
    assert(ankah_disk_session_repair_begin() == 0);
    for (attempts = 0; attempts < 4; ++attempts) {
        assert(queue_snapshot(base, now) == 0);
        ankah_disk_session_state_get(&state);
        if (!state.journal_bad) break;
    }
    assert(!state.journal_bad && !state.poisoned && journal_size(base) == 0);
    stop_writer();
    ankah_session_discard(session);
}

static void test_oversized(const char *base) {
    char journal[560];
    const char record[] = "0123456789abcdef0123456789abcdef\n";
    ankah_disk_session_state state;
    FILE *file;
    size_t i;
    name(journal, sizeof(journal), base, ".journal");
    file = fopen(journal, "wb");
    assert(file);
    for (i = 0; i < ANKAH_JOURNAL_LIMIT / 33U + 10; ++i)
        assert(fwrite(record, 1, 33, file) == 33);
    assert(fclose(file) == 0);
    start_writer(base);
    ankah_disk_session_state_get(&state);
    assert(state.journal_bytes > ANKAH_JOURNAL_LIMIT);
    assert(ankah_disk_maintain() == 0);
    assert(wait_result(ANKAH_DISK_MAINTAIN) == 0);
    assert(journal_size(base) == 0);
    stop_writer();
}

static void test_cap(const char *base, uint64_t now) {
    char id_a[33], token_a[33], id_b[33], token_b[33], journal[560];
    ankah_session *a = new_post(id_a, token_a, now);
    ankah_session *b = new_post(id_b, token_b, now);
    FILE *file;
    size_t i;
    write_initial_slots(base, now);
    name(journal, sizeof(journal), base, ".journal");
    file = fopen(journal, "wb");
    assert(file);
    for (i = 0; i < ANKAH_JOURNAL_LIMIT / 33U; ++i)
        assert(fprintf(file, "%s\n", id_a) == 33);
    assert(fclose(file) == 0);
    start_writer(base);
    assert(consume(base, b, id_b, token_b, now) != 0);
    assert(journal_size(base) == 33U * (ANKAH_JOURNAL_LIMIT / 33U));
    assert(ankah_disk_maintain() == 0);
    assert(wait_result(ANKAH_DISK_MAINTAIN) == 0);
    assert(journal_size(base) == 33);
    assert(consume(base, b, id_b, token_b, now) == 0);
    stop_writer();
    ankah_session_discard(a);
    ankah_session_discard(b);
}

static void test_unknown_slot(const char *base, uint64_t now) {
    char id[33], token[33], path[560], journal[560];
    ankah_session *session = new_post(id, token, now);
    ankah_disk_session_state state;
    FILE *file;
    write_initial_slots(base, now);
    ankah_session_cancel_post(session);
    name(path, sizeof(path), base, ".0");
    file = fopen(path, "wb");
    assert(file);
    assert(fwrite("bad", 1, 3, file) == 3);
    assert(fclose(file) == 0);
    name(journal, sizeof(journal), base, ".journal");
    file = fopen(journal, "wb");
    assert(file);
    assert(fprintf(file, "%s\n", id) == 33);
    assert(fclose(file) == 0);
    start_writer(base);
    ankah_disk_session_state_get(&state);
    assert(state.unknown_slots == 1);
    assert(ankah_disk_maintain() == 0);
    assert(wait_result(ANKAH_DISK_MAINTAIN) != 0);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    ankah_disk_session_state_get(&state);
    assert(state.unknown_slots == 0);
    assert(journal_size(base) == 33);
    assert(queue_snapshot(base, now) == 0);
    assert(journal_size(base) == 0);
    stop_writer();
    ankah_session_discard(session);
}

static void test_append_poison(const char *base, uint64_t now) {
    const char id[] = "0123456789abcdef0123456789abcdef";
    ankah_disk_session_state state;
    unsigned int attempts;
    start_writer(base);
    ankah_disk_test_fail_append_rollback_close_once();
    assert(ankah_disk_consume(base, id, NULL) == 0);
    assert(wait_result(ANKAH_DISK_CONSUME) == -2);
    ankah_disk_session_state_get(&state);
    assert(state.journal_bad && state.poisoned);
    assert(journal_size(base) == 1);
    assert(ankah_disk_session_repair_begin() == 0);
    for (attempts = 0; attempts < 4; ++attempts) {
        assert(queue_snapshot(base, now) == 0);
        ankah_disk_session_state_get(&state);
        if (!state.journal_bad) break;
    }
    assert(!state.journal_bad && journal_size(base) == 0);
    stop_writer();
}

int main(int argc, char **argv) {
    char directory[] = "/tmp/ankah-storage-XXXXXX", base[560], file[560];
    const char *suffixes[] = {".0", ".1", ".tmp", ".journal", ".journal.tmp"};
    size_t i;
    uint64_t now = (uint64_t)time(NULL);
    assert(argc == 2);
    assert(mkdtemp(directory));
    name(base, sizeof(base), directory, "/sessions");
    if (strcmp(argv[1], "building") == 0) test_building(base, now);
    else if (strcmp(argv[1], "queued") == 0) test_queued(base, now);
    else if (strcmp(argv[1], "pending") == 0)
        test_pending_callback(base, now);
    else if (strcmp(argv[1], "priority") == 0)
        test_snapshot_priority(base, now);
    else if (strcmp(argv[1], "snapshot-sync") == 0)
        test_snapshot_sync_failure(base, now);
    else if (strcmp(argv[1], "journal-sync") == 0)
        test_journal_sync_failure(base, now);
    else if (strcmp(argv[1], "repair") == 0) test_malformed_repair(base, now);
    else if (strcmp(argv[1], "oversized") == 0) test_oversized(base);
    else if (strcmp(argv[1], "cap") == 0) test_cap(base, now);
    else if (strcmp(argv[1], "unknown-slot") == 0) test_unknown_slot(base, now);
    else if (strcmp(argv[1], "append-poison") == 0)
        test_append_poison(base, now);
    else assert(0);
    for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        name(file, sizeof(file), base, suffixes[i]);
        remove(file);
    }
    assert(rmdir(directory) == 0);
    return 0;
}
