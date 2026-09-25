#ifndef ANKAH_STATS_H
#define ANKAH_STATS_H

#include <stddef.h>
#include <stdint.h>

#define ANKAH_STAT_SLOTS 48
#define ANKAH_STAT_HOURS 720
#define ANKAH_STAT_DAYS 4096
#define ANKAH_TEXT_MAX (8U * 1024U * 1024U)
#define ANKAH_STATS_PATH_MAX 512

#define ANKAH_STATS_RESTORED 1
#define ANKAH_STATS_DEGRADED 2

/* SUM fields merge by addition, MAX fields by maximum. Order is the wire order. */
#define ANKAH_STAT_FIELDS(SUM, MAX) \
    SUM(client_bytes_in) \
    SUM(client_bytes_out) \
    SUM(upstream_bytes_in) \
    SUM(upstream_bytes_out) \
    SUM(accepted) \
    SUM(refused) \
    SUM(websocket_tunnels) \
    MAX(peak_connections) \
    SUM(requests) \
    SUM(responses_2xx) \
    SUM(responses_3xx) \
    SUM(responses_4xx) \
    SUM(responses_5xx) \
    SUM(rate_limited) \
    SUM(challenges_issued) \
    SUM(challenges_solved) \
    SUM(challenges_failed) \
    SUM(passes_issued) \
    SUM(qr_scans) \
    SUM(posts_saved) \
    SUM(posts_replayed) \
    SUM(static_requests) \
    SUM(static_bytes) \
    SUM(cache_hits) \
    SUM(cache_misses) \
    SUM(upstream_requests) \
    SUM(upstream_failures) \
    SUM(upstream_responses) \
    SUM(upstream_latency_ms_total) \
    MAX(upstream_latency_peak_ms) \
    MAX(peak_sessions) \
    MAX(peak_pending_bytes) \
    SUM(throttled_static_requests) \
    SUM(throttled_static_bytes) \
    SUM(throttle_queue_responses) \
    SUM(throttle_queued_requests) \
    SUM(throttle_wait_ms_total) \
    MAX(throttle_wait_ms_peak) \
    MAX(peak_throttle_connections) \
    MAX(peak_throttle_queue) \
    SUM(rate_limited_anonymous) \
    SUM(rate_limited_protected) \
    SUM(anonymous_connection_rejected) \
    SUM(pending_connection_refused) \
    SUM(challenge_session_rejected)

enum {
#define ANKAH_STAT_ENUM(name) ANKAH_STAT_##name,
    ANKAH_STAT_FIELDS(ANKAH_STAT_ENUM, ANKAH_STAT_ENUM)
#undef ANKAH_STAT_ENUM
    ANKAH_STAT_COUNT
};

typedef struct {
    uint64_t v[ANKAH_STAT_SLOTS];
} ankah_stat_record;

typedef struct {
    char *data;
    size_t size, capacity;
    int failed;
} ankah_text;

void ankah_text_init(ankah_text *text);
void ankah_text_free(ankah_text *text);
void ankah_text_append(ankah_text *text, const char *data, size_t size);
void ankah_text_string(ankah_text *text, const char *string);
void ankah_text_u64(ankah_text *text, uint64_t value);

/* Times are whole seconds since the Unix epoch. Buckets are UTC hours and days. */
void ankah_stats_init(uint64_t wall);
void ankah_stats_add(unsigned int field, uint64_t amount);
void ankah_stats_max(unsigned int field, uint64_t value);
void ankah_stats_roll(uint64_t wall);

/* Restores the newest valid PATH.0 or PATH.1 snapshot, then rolls it to wall.
 * Missing snapshots start a fresh epoch. The return value is a combination of
 * ANKAH_STATS_RESTORED and ANKAH_STATS_DEGRADED. */
int ankah_stats_restore(const char *path, uint64_t wall);
/* Writes the next generation through PATH.tmp into the older snapshot slot. */
int ankah_stats_save(const char *path, uint64_t wall);

const char *ankah_stat_name(unsigned int field);
int ankah_stat_is_max(unsigned int field);
uint64_t ankah_stats_epoch(void);
uint64_t ankah_stats_hour_index(void);
uint64_t ankah_stats_day_index(void);
uint64_t ankah_stats_evicted_days(void);
size_t ankah_stats_hour_count(void);
size_t ankah_stats_day_count(void);
const ankah_stat_record *ankah_stats_cumulative(void);
const ankah_stat_record *ankah_stats_current_hour(void);
const ankah_stat_record *ankah_stats_current_day(void);
const ankah_stat_record *ankah_stats_evicted(void);
/* Age 0 is the most recently completed bucket. NULL when out of range. */
const ankah_stat_record *ankah_stats_hour(size_t age);
const ankah_stat_record *ankah_stats_day(size_t age);

/* The JSON writers emit members without enclosing braces so the caller can
 * add its own members. JSON rows are arrays of ANKAH_STAT_COUNT numbers. */
void ankah_stats_write_schema(ankah_text *out);
void ankah_stats_write_live(ankah_text *out);
void ankah_stats_write_history(ankah_text *out, size_t hours, size_t days);
/* Writes a complete, non-overlapping CSV timeline through wall. */
void ankah_stats_write_csv(ankah_text *out, uint64_t wall);

#endif
