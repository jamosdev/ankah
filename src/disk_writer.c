#include "disk_writer.h"
#include "ankah/files.h"
#include "ankah/session.h"

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifdef ANKAH_STORAGE_TEST
#include <assert.h>
#endif
#ifndef _WIN32
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
extern long syscall(long number, ...);
#elif defined(__APPLE__)
#include <pthread.h>
#endif
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#endif

typedef struct disk_task disk_task;
typedef struct {
    char (*ids)[33];
    size_t count;
    int unknown;
} snapshot_index;

enum {
    SESSION_IDLE, SESSION_BUILDING, SESSION_QUEUED,
    SESSION_WRITING, SESSION_WAIT_CALLBACK
};

struct disk_task {
    disk_task *next;
    disk_task *pending_prev, *pending_next;
    int kind, result;
    char path[512];
    char id[33];
    unsigned char *data;
    size_t size;
    uint64_t generation;
    void *context;
};

typedef struct {
    uv_mutex_t mutex;
    uv_cond_t condition;
    uv_thread_t thread;
    uv_async_t async;
    ankah_disk_result_cb callback;
    void *owner;
    disk_task *stats, *sessions, *consume_first, *consume_last;
    disk_task *maintenance;
    disk_task *log_first, *log_last;
    disk_task *done_first, *done_last;
    /* Completed consumptions stay here until their main-loop callbacks settle
     * the saved POSTs. Compaction must retain their journal IDs meanwhile. */
    disk_task *pending_consume_first, *pending_consume_last;
    int running, stopping, exited;
    int journal_poisoned;
    int journal_bad, repair_started, compacting, session_phase;
    unsigned int repair_slots;
    char session_path[512];
    snapshot_index slots[2];
    size_t journal_bytes;
    unsigned int consumption_count;
    size_t pending_consume_count;
    size_t log_bytes;
} disk_writer;

static disk_writer writer;

#ifdef ANKAH_STORAGE_TEST
static uv_sem_t maintenance_entered, maintenance_release;
static int pause_maintenance;
static int fail_append_rollback_close;

void ankah_disk_test_pause_maintenance(void) {
    assert(uv_sem_init(&maintenance_entered, 0) == 0);
    assert(uv_sem_init(&maintenance_release, 0) == 0);
    pause_maintenance = 1;
}

void ankah_disk_test_wait_maintenance(void) {
    uv_sem_wait(&maintenance_entered);
}

void ankah_disk_test_resume_maintenance(void) {
    uv_sem_post(&maintenance_release);
    pause_maintenance = 0;
}

void ankah_disk_test_fail_append_rollback_close_once(void) {
    fail_append_rollback_close = 1;
}

void ankah_disk_test_wait_pending_results(size_t count) {
    size_t attempt;
    for (attempt = 0; attempt < 30000; ++attempt) {
        disk_task *task;
        size_t pending = 0;
        uv_mutex_lock(&writer.mutex);
        for (task = writer.done_first; task; task = task->next) ++pending;
        uv_mutex_unlock(&writer.mutex);
        if (pending >= count) return;
        uv_sleep(1);
    }
    assert(0);
}
#endif

static void lower_priority(void) {
#ifdef __linux__
    if (setpriority(PRIO_PROCESS, 0, 19) != 0)
        fprintf(stderr, "Ankah disk writer CPU priority: %s\n", strerror(errno));
#if defined(SYS_ioprio_set)
    /* IOPRIO_WHO_PROCESS=1, idle class=3. The current Linux task is this thread. */
    if (syscall(SYS_ioprio_set, 1, 0, 3 << 13) != 0)
        fprintf(stderr, "Ankah disk writer I/O priority: %s\n", strerror(errno));
#endif
#elif defined(_WIN32)
    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE))
        fprintf(stderr, "Ankah disk writer CPU priority could not be lowered\n");
    if (!SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN))
        fprintf(stderr, "Ankah disk writer I/O priority could not be lowered\n");
#elif defined(__APPLE__)
    if (pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0) != 0)
        fprintf(stderr, "Ankah disk writer background priority unavailable\n");
#else
    fprintf(stderr, "Ankah disk writer background priority unavailable\n");
#endif
}

#ifndef _WIN32
static int sync_parent(const char *path) {
    char directory[512];
    const char *slash = strrchr(path, '/');
    size_t length = slash ? (size_t)(slash - path) : 0;
    int fd, result;
    if (!slash) strcpy(directory, ".");
    else if (!length) strcpy(directory, "/");
    else {
        if (length >= sizeof(directory)) return -1;
        memcpy(directory, path, length);
        directory[length] = 0;
    }
    fd = open(directory, O_RDONLY);
    if (fd < 0) return -1;
    result = fsync(fd);
    if (close(fd) != 0) result = -1;
    return result;
}
#endif

static int compare_ids(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static void sort_ids(snapshot_index *index) {
    size_t read_at, write_at = 0;
    if (index->count) qsort(index->ids, index->count, 33, compare_ids);
    for (read_at = 0; read_at < index->count; ++read_at) {
        if (write_at && strcmp(index->ids[read_at], index->ids[write_at - 1]) == 0)
            continue;
        if (write_at != read_at) memcpy(index->ids[write_at], index->ids[read_at], 33);
        ++write_at;
    }
    index->count = write_at;
}

static int image_index(const unsigned char *data, size_t size,
                       snapshot_index *index) {
    index->ids = malloc(ANKAH_SESSION_CAPACITY * 33U);
    if (!index->ids) return -1;
    if (ankah_session_snapshot_saved_ids(data, size, index->ids,
                                         ANKAH_SESSION_CAPACITY,
                                         &index->count) != 0) {
        free(index->ids);
        index->ids = NULL;
        return -1;
    }
    sort_ids(index);
    return 0;
}

static void load_slot(const char *path, int slot, snapshot_index *index) {
    char name[528];
    unsigned char *data = NULL;
    size_t size = 0;
    int n = snprintf(name, sizeof(name), "%s.%d", path, slot);
    int result = n < 0 || (size_t)n >= sizeof(name) ? -1 :
        ankah_file_read_optional(name, ANKAH_SESSION_SNAPSHOT_MAX, 1,
                                 &data, &size);
    if (result == 0) {
        if (image_index(data, size, index) != 0) index->unknown = 1;
    } else if (result < 0) index->unknown = 1;
    free(data);
}

static void merge_failed_slot(snapshot_index *slot, snapshot_index *candidate) {
    size_t combined;
    char (*ids)[33];
    if (slot->unknown) return;
    combined = slot->count + candidate->count;
    if (combined > 2U * ANKAH_SESSION_CAPACITY) {
        slot->unknown = 1;
        return;
    }
    ids = realloc(slot->ids, (combined ? combined : 1) * 33U);
    if (!ids) {
        slot->unknown = 1;
        return;
    }
    slot->ids = ids;
    if (candidate->count)
        memcpy(slot->ids + slot->count, candidate->ids, candidate->count * 33U);
    slot->count = combined;
    sort_ids(slot);
}

static int journal_name(const char *base, char name[528]) {
    int n = snprintf(name, 528, "%s.journal", base);
    return n < 0 || n >= 528 ? -1 : 0;
}

static FILE *open_journal_read(const char *path, int *missing) {
    FILE *file;
    *missing = 0;
#ifndef _WIN32
    int flags = O_RDONLY;
    int fd;
    struct stat metadata;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(path, flags);
    if (fd < 0) {
        if (errno == ENOENT) *missing = 1;
        return NULL;
    }
    if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
        close(fd);
        return NULL;
    }
    file = fdopen(fd, "rb");
    if (!file) close(fd);
#else
    file = fopen(path, "rb");
    if (!file && errno == ENOENT) *missing = 1;
#endif
    return file;
}

static int valid_record(const char record[33]) {
    size_t i;
    if (record[32] != '\n') return 0;
    for (i = 0; i < 32; ++i)
        if (!((record[i] >= '0' && record[i] <= '9') ||
              (record[i] >= 'a' && record[i] <= 'f'))) return 0;
    return 1;
}

static int scan_journal(const char *path, size_t *bytes) {
    char record[33];
    int missing, bad = 0;
    FILE *file = open_journal_read(path, &missing);
    *bytes = 0;
    if (!file) return missing ? 0 : -1;
    for (;;) {
        size_t amount = fread(record, 1, sizeof(record), file);
        if (amount == 0 && feof(file)) break;
        if (amount != sizeof(record) || !valid_record(record) ||
            *bytes > SIZE_MAX - sizeof(record)) { bad = 1; break; }
        *bytes += sizeof(record);
    }
    if (ferror(file)) bad = 1;
    if (fclose(file) != 0) bad = 1;
    return bad ? -1 : 0;
}

static unsigned int unknown_slots(void) {
    return (writer.slots[0].unknown ? 1U : 0U) |
           (writer.slots[1].unknown ? 2U : 0U);
}

static void mark_journal_bad(void) {
    uv_mutex_lock(&writer.mutex);
    writer.journal_bad = writer.journal_poisoned = 1;
    uv_mutex_unlock(&writer.mutex);
}

static int compact_journal(int force_replace) {
    snapshot_index retained = {0};
    char path[528], temp[536], record[33], key[33];
    unsigned char *seen = NULL, *data = NULL;
    size_t source_bytes = 0, output_bytes = 0, i;
    int missing, result = -1;
    FILE *file = NULL;
    uv_mutex_lock(&writer.mutex);
    if (writer.compacting || writer.journal_bad || writer.repair_started ||
        (writer.journal_poisoned && !force_replace) || unknown_slots() ||
        writer.session_phase == SESSION_BUILDING ||
        writer.session_phase == SESSION_QUEUED ||
        writer.session_phase == SESSION_WRITING) {
        uv_mutex_unlock(&writer.mutex);
        return -1;
    }
    writer.compacting = 1;
    uv_mutex_unlock(&writer.mutex);
    if (journal_name(writer.session_path, path) != 0 ||
        snprintf(temp, sizeof(temp), "%s.tmp", path) >= (int)sizeof(temp))
        goto done;
    /* Only the main loop can remove pending callbacks while this worker
     * compacts; this worker cannot add another one until compaction ends. */
    uv_mutex_lock(&writer.mutex);
    retained.count = writer.slots[0].count + writer.slots[1].count +
                     writer.pending_consume_count;
    uv_mutex_unlock(&writer.mutex);
    retained.ids = malloc((retained.count ? retained.count : 1) * 33U);
    if (!retained.ids) goto done;
    if (writer.slots[0].count)
        memcpy(retained.ids, writer.slots[0].ids, writer.slots[0].count * 33U);
    if (writer.slots[1].count)
        memcpy(retained.ids + writer.slots[0].count, writer.slots[1].ids,
               writer.slots[1].count * 33U);
    retained.count = writer.slots[0].count + writer.slots[1].count;
    uv_mutex_lock(&writer.mutex);
    {
        disk_task *pending;
        for (pending = writer.pending_consume_first; pending;
             pending = pending->pending_next)
            memcpy(retained.ids[retained.count++], pending->id, 33);
    }
    uv_mutex_unlock(&writer.mutex);
    sort_ids(&retained);
    seen = calloc(retained.count ? retained.count : 1, 1);
    if (!seen) goto done;
    file = open_journal_read(path, &missing);
    if (!file && !missing) {
        mark_journal_bad();
        goto done;
    }
    if (file) {
        for (;;) {
            char (*found)[33];
            size_t amount = fread(record, 1, sizeof(record), file);
            if (amount == 0 && feof(file)) break;
            if (amount != sizeof(record) || !valid_record(record) ||
                source_bytes > SIZE_MAX - sizeof(record)) {
                mark_journal_bad();
                goto done;
            }
            source_bytes += sizeof(record);
            memcpy(key, record, 32);
            key[32] = 0;
            found = bsearch(key, retained.ids, retained.count, 33, compare_ids);
            if (found) seen[found - retained.ids] = 1;
        }
        if (ferror(file)) {
            mark_journal_bad();
            goto done;
        }
        if (fclose(file) != 0) {
            file = NULL;
            mark_journal_bad();
            goto done;
        }
        file = NULL;
    }
    for (i = 0; i < retained.count; ++i)
        if (seen[i]) output_bytes += 33;
    if (!force_replace && output_bytes == source_bytes) {
        result = 0;
        goto done;
    }
    data = malloc(output_bytes ? output_bytes : 1);
    if (!data) goto done;
    output_bytes = 0;
    for (i = 0; i < retained.count; ++i) {
        if (!seen[i]) continue;
        memcpy(data + output_bytes, retained.ids[i], 32);
        data[output_bytes + 32] = '\n';
        output_bytes += 33;
    }
    if (ankah_file_replace(temp, path, data, output_bytes) != 0) {
        uv_mutex_lock(&writer.mutex);
        writer.journal_poisoned = 1;
        uv_mutex_unlock(&writer.mutex);
        goto done;
    }
    result = 0;
    source_bytes = output_bytes;
done:
    if (file) fclose(file);
    uv_mutex_lock(&writer.mutex);
    if (result == 0) {
        writer.journal_bytes = source_bytes;
        writer.journal_poisoned = 0;
    }
    writer.compacting = 0;
    uv_mutex_unlock(&writer.mutex);
    free(data);
    free(seen);
    free(retained.ids);
    return result;
}

static int append_consumption(const disk_task *task) {
    char path[sizeof(task->path) + 16];
    int n = snprintf(path, sizeof(path), "%s.journal", task->path);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
#ifdef _WIN32
    {
        int fd = _open(path, _O_WRONLY | _O_CREAT | _O_APPEND | _O_BINARY,
                       _S_IREAD | _S_IWRITE);
        __int64 before;
        char record[33];
        int result = 0, written;
        if (fd < 0) return -1;
        before = _lseeki64(fd, 0, SEEK_END);
        if (before < 0) { _close(fd); return -1; }
        memcpy(record, task->id, 32);
        record[32] = '\n';
        written = _write(fd, record, sizeof(record));
        if (written != (int)sizeof(record) || _commit(fd) != 0) {
            result = -1;
            if (written > 0 && (_chsize_s(fd, before) != 0 || _commit(fd) != 0))
                result = -2;
        }
        if (_close(fd) != 0 && result != -2) result = -1;
        return result;
    }
#else
    {
        int flags = O_WRONLY | O_CREAT | O_APPEND;
        int fd;
        struct stat metadata;
        off_t before;
        char record[33];
        size_t used = 0;
        int result = 0;
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        fd = open(path, flags, 0600);
        if (fd < 0) return -1;
        if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            fchmod(fd, S_IRUSR | S_IWUSR) != 0 ||
            (before = lseek(fd, 0, SEEK_END)) < 0) {
            close(fd);
            return -1;
        }
        memcpy(record, task->id, 32); record[32] = '\n';
#ifdef ANKAH_STORAGE_TEST
        if (fail_append_rollback_close) {
            if (write(fd, record, 1) != 1) {
                close(fd);
                return -1;
            }
            used = 1;
            result = -1;
        }
#endif
        while (result == 0 && used < sizeof(record)) {
            ssize_t amount = write(fd, record + used, sizeof(record) - used);
            if (amount < 0 && errno == EINTR) continue;
            if (amount <= 0) { result = -1; break; }
            used += (size_t)amount;
        }
        if (result == 0 && fsync(fd) != 0) result = -1;
        if (result == 0 && sync_parent(path) != 0) result = -1;
        if (result != 0 && used) {
#ifdef ANKAH_STORAGE_TEST
            if (fail_append_rollback_close) result = -2;
            else
#endif
            if (ftruncate(fd, before) != 0 || fsync(fd) != 0) result = -2;
        }
#ifdef ANKAH_STORAGE_TEST
        if (fail_append_rollback_close) {
            close(fd);
            fail_append_rollback_close = 0;
            if (result != -2) result = -1;
        } else
#endif
        if (close(fd) != 0 && result != -2) result = -1;
        return result;
    }
#endif
}

static int append_log(const disk_task *task) {
#ifdef _WIN32
    int fd = _open(task->path, _O_WRONLY | _O_CREAT | _O_APPEND | _O_BINARY,
                   _S_IREAD | _S_IWRITE);
    size_t used = 0;
    int result = 0;
    if (fd < 0) return -1;
    while (used < task->size) {
        unsigned int amount = task->size - used > INT_MAX ?
            INT_MAX : (unsigned int)(task->size - used);
        int written = _write(fd, task->data + used, amount);
        if (written <= 0) { result = -1; break; }
        used += (size_t)written;
    }
    if (result == 0 && _commit(fd) != 0) result = -1;
    if (_close(fd) != 0) result = -1;
    return result;
#else
    int flags = O_WRONLY | O_CREAT | O_APPEND;
    int fd, result = 0;
    size_t used = 0;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(task->path, flags, 0600);
    if (fd < 0) return -1;
    while (used < task->size) {
        ssize_t amount = write(fd, task->data + used, task->size - used);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { result = -1; break; }
        used += (size_t)amount;
    }
    if (result == 0 && fsync(fd) != 0) result = -1;
    if (close(fd) != 0) result = -1;
    return result;
#endif
}

static int write_snapshot(const disk_task *task) {
    char temp[sizeof(task->path) + 8], target[sizeof(task->path) + 8];
    int n = snprintf(temp, sizeof(temp), "%s.tmp", task->path);
    if (n < 0 || (size_t)n >= sizeof(temp)) return -1;
    n = snprintf(target, sizeof(target), "%s.%d", task->path,
                 (int)(task->generation & 1));
    if (n < 0 || (size_t)n >= sizeof(target)) return -1;
    return ankah_file_replace(temp, target, task->data, task->size);
}

static int reset_journal(void) {
    char path[528], temp[536];
    unsigned char empty = 0;
    size_t bytes;
    if (journal_name(writer.session_path, path) != 0 ||
        snprintf(temp, sizeof(temp), "%s.tmp", path) >= (int)sizeof(temp) ||
        ankah_file_replace(temp, path, &empty, 0) != 0 ||
        scan_journal(path, &bytes) != 0 || bytes != 0) return -1;
    uv_mutex_lock(&writer.mutex);
    writer.journal_bytes = 0;
    writer.journal_bad = writer.journal_poisoned = 0;
    writer.repair_started = 0;
    uv_mutex_unlock(&writer.mutex);
    return 0;
}

static int recover_ambiguous_journal(void) {
    char path[528];
    size_t bytes;
    if (journal_name(writer.session_path, path) != 0) return -1;
#ifndef _WIN32
    if (sync_parent(path) != 0 || scan_journal(path, &bytes) != 0) return -1;
    uv_mutex_lock(&writer.mutex);
    writer.journal_bytes = bytes;
    writer.journal_poisoned = 0;
    uv_mutex_unlock(&writer.mutex);
    return 0;
#else
    if (scan_journal(path, &bytes) != 0) return -1;
    return compact_journal(1);
#endif
}

static int maintain_journal(void) {
    int bad, repair, poisoned;
    unsigned int repair_slots;
    size_t bytes;
    uv_mutex_lock(&writer.mutex);
    bad = writer.journal_bad;
    repair = writer.repair_started;
    repair_slots = writer.repair_slots;
    poisoned = writer.journal_poisoned;
    bytes = writer.journal_bytes;
    uv_mutex_unlock(&writer.mutex);
    if (bad) return repair && !repair_slots ? reset_journal() : -1;
    if (poisoned && recover_ambiguous_journal() != 0) return -1;
    if (bytes || poisoned) return compact_journal(0);
    return 0;
}

static int write_session_snapshot(const disk_task *task) {
    snapshot_index candidate = {0};
    snapshot_index *slot;
    int result, number = (int)(task->generation & 1);
    if (image_index(task->data, task->size, &candidate) != 0) {
        uv_mutex_lock(&writer.mutex);
        writer.session_phase = SESSION_WAIT_CALLBACK;
        uv_mutex_unlock(&writer.mutex);
        return -1;
    }
    result = write_snapshot(task);
    uv_mutex_lock(&writer.mutex);
    slot = &writer.slots[number];
    if (result == 0) {
        free(slot->ids);
        *slot = candidate;
        candidate.ids = NULL;
        if (writer.repair_started) writer.repair_slots &= ~(1U << number);
    } else merge_failed_slot(slot, &candidate);
    writer.session_phase = SESSION_WAIT_CALLBACK;
    uv_mutex_unlock(&writer.mutex);
    free(candidate.ids);
    (void)maintain_journal();
    return result;
}

static void writer_thread(void *ignored) {
    (void)ignored;
    lower_priority();
    for (;;) {
        disk_task *task;
        uv_mutex_lock(&writer.mutex);
        while (!writer.consume_first && !writer.sessions && !writer.stats &&
               !writer.log_first && !writer.maintenance &&
               !writer.stopping)
            uv_cond_wait(&writer.condition, &writer.mutex);
        if (writer.maintenance) {
            task = writer.maintenance;
            writer.maintenance = NULL;
        /* A continuous consume queue must not starve the snapshot needed to
         * reduce a growing journal or replace an unreadable slot. */
        } else if (writer.sessions &&
                   (!writer.consume_first ||
                    writer.journal_bytes >= ANKAH_JOURNAL_REFRESH ||
                    writer.repair_started || writer.journal_bad ||
                    writer.journal_poisoned || unknown_slots())) {
            task = writer.sessions;
            writer.sessions = NULL;
            writer.session_phase = SESSION_WRITING;
        } else if (writer.consume_first) {
            task = writer.consume_first;
            writer.consume_first = task->next;
            if (!writer.consume_first) writer.consume_last = NULL;
            --writer.consumption_count;
        } else if (writer.stats) {
            task = writer.stats;
            writer.stats = NULL;
        } else if (writer.log_first) {
            task = writer.log_first;
            writer.log_first = task->next;
            if (!writer.log_first) writer.log_last = NULL;
            writer.log_bytes -= task->size;
        } else {
            writer.exited = 1;
            uv_mutex_unlock(&writer.mutex);
            uv_async_send(&writer.async);
            return;
        }
        uv_mutex_unlock(&writer.mutex);
#ifdef ANKAH_STORAGE_TEST
        if (task->kind == ANKAH_DISK_MAINTAIN && pause_maintenance) {
            uv_sem_post(&maintenance_entered);
            uv_sem_wait(&maintenance_release);
        }
#endif
        if (task->kind == ANKAH_DISK_CONSUME) {
            int blocked;
            uv_mutex_lock(&writer.mutex);
            blocked = writer.journal_poisoned || writer.journal_bad ||
                writer.journal_bytes > ANKAH_JOURNAL_LIMIT - 33;
            uv_mutex_unlock(&writer.mutex);
            task->result = blocked ? -1 : append_consumption(task);
            if (!blocked) {
                if (task->result == 0) {
                    uv_mutex_lock(&writer.mutex);
                    writer.journal_bytes += 33;
                    uv_mutex_unlock(&writer.mutex);
                } else if (task->result == -2) mark_journal_bad();
                else {
                    char path[528];
                    size_t bytes;
                    if (journal_name(task->path, path) != 0 ||
                        scan_journal(path, &bytes) != 0) mark_journal_bad();
                    else {
                        uv_mutex_lock(&writer.mutex);
                        writer.journal_bytes = bytes;
                        uv_mutex_unlock(&writer.mutex);
                    }
                }
            }
        } else if (task->kind == ANKAH_DISK_LOG)
            task->result = append_log(task);
        else if (task->kind == ANKAH_DISK_SESSIONS)
            task->result = write_session_snapshot(task);
        else if (task->kind == ANKAH_DISK_MAINTAIN)
            task->result = maintain_journal();
        else task->result = write_snapshot(task);
        free(task->data);
        task->data = NULL;
        uv_mutex_lock(&writer.mutex);
        if (task->kind == ANKAH_DISK_CONSUME) {
            task->pending_prev = writer.pending_consume_last;
            if (writer.pending_consume_last)
                writer.pending_consume_last->pending_next = task;
            else writer.pending_consume_first = task;
            writer.pending_consume_last = task;
            ++writer.pending_consume_count;
        }
        task->next = NULL;
        if (writer.done_last) writer.done_last->next = task;
        else writer.done_first = task;
        writer.done_last = task;
        uv_mutex_unlock(&writer.mutex);
        uv_async_send(&writer.async);
    }
}

static void on_async(uv_async_t *handle) {
    disk_task *done;
    int exited;
    (void)handle;
    uv_mutex_lock(&writer.mutex);
    done = writer.done_first;
    writer.done_first = writer.done_last = NULL;
    exited = writer.exited;
    uv_mutex_unlock(&writer.mutex);
    while (done) {
        disk_task *next = done->next;
        writer.callback(done->kind, done->context, done->result,
                        done->generation, writer.owner);
        if (done->kind == ANKAH_DISK_CONSUME) {
            uv_mutex_lock(&writer.mutex);
            if (done->pending_prev)
                done->pending_prev->pending_next = done->pending_next;
            else writer.pending_consume_first = done->pending_next;
            if (done->pending_next)
                done->pending_next->pending_prev = done->pending_prev;
            else writer.pending_consume_last = done->pending_prev;
            --writer.pending_consume_count;
            uv_mutex_unlock(&writer.mutex);
        }
        free(done);
        done = next;
    }
    if (exited) uv_close((uv_handle_t *)&writer.async, NULL);
}

int ankah_disk_start(uv_loop_t *loop, ankah_disk_result_cb callback, void *owner,
                     const char *session_path) {
    char path[528];
    memset(&writer, 0, sizeof(writer));
    writer.callback = callback;
    writer.owner = owner;
    if (session_path && session_path[0]) {
        size_t bytes;
        if (strlen(session_path) >= sizeof(writer.session_path)) return -1;
        strcpy(writer.session_path, session_path);
        load_slot(session_path, 0, &writer.slots[0]);
        load_slot(session_path, 1, &writer.slots[1]);
        if (journal_name(session_path, path) != 0 ||
            scan_journal(path, &bytes) != 0)
            writer.journal_bad = writer.journal_poisoned = 1;
        else writer.journal_bytes = bytes;
    }
    if (uv_mutex_init(&writer.mutex) != 0) goto failed;
    if (uv_cond_init(&writer.condition) != 0) {
        uv_mutex_destroy(&writer.mutex); goto failed;
    }
    if (uv_async_init(loop, &writer.async, on_async) != 0) {
        uv_cond_destroy(&writer.condition);
        uv_mutex_destroy(&writer.mutex); goto failed;
    }
    if (uv_thread_create(&writer.thread, writer_thread, NULL) != 0) {
        uv_close((uv_handle_t *)&writer.async, NULL);
        uv_cond_destroy(&writer.condition);
        uv_mutex_destroy(&writer.mutex); goto failed;
    }
    writer.running = 1;
    return 0;
failed:
    free(writer.slots[0].ids);
    free(writer.slots[1].ids);
    return -1;
}

int ankah_disk_snapshot(int kind, const char *path, unsigned char *data,
                        size_t size, uint64_t generation) {
    disk_task *task, **slot;
    if (!writer.running || !data || (kind != ANKAH_DISK_STATS &&
        kind != ANKAH_DISK_SESSIONS) || strlen(path) >= sizeof(task->path)) return -1;
    task = calloc(1, sizeof(*task));
    if (!task) return -1;
    task->kind = kind;
    task->data = data;
    task->size = size;
    task->generation = generation;
    strcpy(task->path, path);
    uv_mutex_lock(&writer.mutex);
    if (writer.stopping || (kind == ANKAH_DISK_SESSIONS &&
        (writer.session_phase != SESSION_BUILDING || writer.sessions))) {
        uv_mutex_unlock(&writer.mutex); free(task); return -1;
    }
    slot = kind == ANKAH_DISK_STATS ? &writer.stats : &writer.sessions;
    if (kind == ANKAH_DISK_STATS && *slot) {
        free((*slot)->data);
        free(*slot);
    }
    *slot = task;
    if (kind == ANKAH_DISK_SESSIONS) writer.session_phase = SESSION_QUEUED;
    uv_cond_signal(&writer.condition);
    uv_mutex_unlock(&writer.mutex);
    return 0;
}

int ankah_disk_session_capture_begin(void) {
    int result = -1;
    if (!writer.running) return -1;
    uv_mutex_lock(&writer.mutex);
    if (!writer.stopping && !writer.compacting &&
        writer.session_phase == SESSION_IDLE) {
        writer.session_phase = SESSION_BUILDING;
        result = 0;
    }
    uv_mutex_unlock(&writer.mutex);
    return result;
}

void ankah_disk_session_capture_cancel(void) {
    if (!writer.running) return;
    uv_mutex_lock(&writer.mutex);
    if (writer.session_phase == SESSION_BUILDING)
        writer.session_phase = SESSION_IDLE;
    uv_mutex_unlock(&writer.mutex);
}

void ankah_disk_session_result_done(void) {
    if (!writer.running) return;
    uv_mutex_lock(&writer.mutex);
    if (writer.session_phase == SESSION_WAIT_CALLBACK)
        writer.session_phase = SESSION_IDLE;
    uv_mutex_unlock(&writer.mutex);
}

void ankah_disk_session_state_get(ankah_disk_session_state *state) {
    memset(state, 0, sizeof(*state));
    if (!writer.running) return;
    uv_mutex_lock(&writer.mutex);
    state->journal_bytes = writer.journal_bytes;
    state->unknown_slots = unknown_slots();
    state->repair_slots = writer.repair_slots;
    state->journal_bad = writer.journal_bad;
    state->poisoned = writer.journal_poisoned;
    state->repair_started = writer.repair_started;
    uv_mutex_unlock(&writer.mutex);
}

int ankah_disk_session_repair_begin(void) {
    int result = -1;
    if (!writer.running) return -1;
    uv_mutex_lock(&writer.mutex);
    if (writer.journal_bad && !writer.repair_started &&
        writer.session_phase == SESSION_IDLE) {
        writer.repair_started = 1;
        writer.repair_slots = 3;
        result = 0;
    }
    uv_mutex_unlock(&writer.mutex);
    return result;
}

int ankah_disk_maintain(void) {
    disk_task *task;
    if (!writer.running || !writer.session_path[0]) return -1;
    task = calloc(1, sizeof(*task));
    if (!task) return -1;
    task->kind = ANKAH_DISK_MAINTAIN;
    uv_mutex_lock(&writer.mutex);
    if (writer.stopping || writer.maintenance) {
        uv_mutex_unlock(&writer.mutex);
        free(task);
        return -1;
    }
    writer.maintenance = task;
    uv_cond_signal(&writer.condition);
    uv_mutex_unlock(&writer.mutex);
    return 0;
}

int ankah_disk_consume(const char *path, const char id[33], void *context) {
    disk_task *task;
    if (!writer.running || strlen(path) >= sizeof(task->path)) return -1;
    task = calloc(1, sizeof(*task));
    if (!task) return -1;
    task->kind = ANKAH_DISK_CONSUME;
    task->context = context;
    strcpy(task->path, path);
    memcpy(task->id, id, 33);
    uv_mutex_lock(&writer.mutex);
    if (writer.stopping || writer.consumption_count >= 4096) {
        uv_mutex_unlock(&writer.mutex); free(task); return -1;
    }
    if (writer.consume_last) writer.consume_last->next = task;
    else writer.consume_first = task;
    writer.consume_last = task;
    ++writer.consumption_count;
    uv_cond_signal(&writer.condition);
    uv_mutex_unlock(&writer.mutex);
    return 0;
}

int ankah_disk_log(const char *path, const char *data, size_t size) {
    disk_task *task;
    if (!writer.running || !path || !data || !size ||
        strlen(path) >= sizeof(task->path) || size > 1024U * 1024U) return -1;
    task = calloc(1, sizeof(*task));
    if (!task) return -1;
    task->data = malloc(size);
    if (!task->data) { free(task); return -1; }
    memcpy(task->data, data, size);
    task->size = size;
    task->kind = ANKAH_DISK_LOG;
    strcpy(task->path, path);
    uv_mutex_lock(&writer.mutex);
    if (writer.stopping || writer.log_bytes > 1024U * 1024U - size) {
        uv_mutex_unlock(&writer.mutex);
        free(task->data); free(task);
        return -1;
    }
    if (writer.log_last) writer.log_last->next = task;
    else writer.log_first = task;
    writer.log_last = task;
    writer.log_bytes += size;
    uv_cond_signal(&writer.condition);
    uv_mutex_unlock(&writer.mutex);
    return 0;
}

void ankah_disk_stop(void) {
    if (!writer.running) return;
    uv_mutex_lock(&writer.mutex);
    writer.stopping = 1;
    uv_cond_signal(&writer.condition);
    uv_mutex_unlock(&writer.mutex);
}

int ankah_disk_pending(void) {
    int pending;
    if (!writer.running) return 0;
    uv_mutex_lock(&writer.mutex);
    pending = writer.consume_first || writer.sessions || writer.stats ||
              writer.log_first || writer.maintenance;
    uv_mutex_unlock(&writer.mutex);
    return pending;
}

void ankah_disk_join(void) {
    if (!writer.running) return;
    uv_thread_join(&writer.thread);
    free(writer.slots[0].ids);
    free(writer.slots[1].ids);
    uv_cond_destroy(&writer.condition);
    uv_mutex_destroy(&writer.mutex);
    writer.running = 0;
}
