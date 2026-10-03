#ifndef ANKAH_DISK_WRITER_H
#define ANKAH_DISK_WRITER_H

#include <stddef.h>
#include <stdint.h>
#include <uv.h>

enum {
    ANKAH_DISK_STATS = 1, ANKAH_DISK_SESSIONS = 2,
    ANKAH_DISK_CONSUME = 3, ANKAH_DISK_LOG = 4,
    ANKAH_DISK_MAINTAIN = 5
};

#define ANKAH_JOURNAL_LIMIT (1024U * 1024U)
#define ANKAH_JOURNAL_REFRESH (256U * 1024U)

typedef struct {
    size_t journal_bytes;
    unsigned int unknown_slots, repair_slots;
    int journal_bad, poisoned, repair_started;
} ankah_disk_session_state;

typedef void (*ankah_disk_result_cb)(int kind, void *context, int result,
                                     uint64_t generation, void *owner);

int ankah_disk_start(uv_loop_t *loop, ankah_disk_result_cb callback, void *owner,
                     const char *session_path);
/* Takes ownership of data on success. Snapshot mailboxes hold one pending buffer
 * per kind. Session snapshots require a capture gate and cannot be replaced. */
int ankah_disk_snapshot(int kind, const char *path, unsigned char *data,
                        size_t size, uint64_t generation);
int ankah_disk_session_capture_begin(void);
void ankah_disk_session_capture_cancel(void);
void ankah_disk_session_result_done(void);
void ankah_disk_session_state_get(ankah_disk_session_state *state);
int ankah_disk_session_repair_begin(void);
int ankah_disk_maintain(void);
/* Acknowledged after the append and sync complete. */
int ankah_disk_consume(const char *path, const char id[33], void *context);
int ankah_disk_log(const char *path, const char *data, size_t size);
void ankah_disk_stop(void);
void ankah_disk_join(void);
int ankah_disk_pending(void);
#ifdef ANKAH_STORAGE_TEST
void ankah_disk_test_pause_maintenance(void);
void ankah_disk_test_wait_maintenance(void);
void ankah_disk_test_resume_maintenance(void);
void ankah_disk_test_fail_append_rollback_close_once(void);
void ankah_disk_test_wait_pending_results(size_t count);
#endif

#endif
