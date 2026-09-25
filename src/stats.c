#include "ankah/stats.h"
#include "ankah/files.h"
#include "ankah/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Fails to compile when the field list outgrows the record. */
typedef char ankah_stat_fields_fit[ANKAH_STAT_COUNT <= ANKAH_STAT_SLOTS ? 1 : -1];

typedef struct {
    ankah_stat_record *rows;
    size_t capacity, head, count;
} stat_ring;

typedef struct {
    int enabled;
    uint64_t epoch, hour_index, day_index, evicted_days;
    ankah_stat_record cumulative, hour, day, evicted;
    ankah_stat_record hour_rows[ANKAH_STAT_HOURS];
    ankah_stat_record day_rows[ANKAH_STAT_DAYS];
} stat_state;

static stat_state stats;
static uint64_t snapshot_generation;

static stat_ring hours = {stats.hour_rows, ANKAH_STAT_HOURS, 0, 0};
static stat_ring days = {stats.day_rows, ANKAH_STAT_DAYS, 0, 0};

static const char *const names[ANKAH_STAT_COUNT] = {
#define ANKAH_STAT_NAME(name) #name,
    ANKAH_STAT_FIELDS(ANKAH_STAT_NAME, ANKAH_STAT_NAME)
#undef ANKAH_STAT_NAME
};

static const unsigned char maxima[ANKAH_STAT_COUNT] = {
#define ANKAH_STAT_SUM(name) 0,
#define ANKAH_STAT_MAX(name) 1,
    ANKAH_STAT_FIELDS(ANKAH_STAT_SUM, ANKAH_STAT_MAX)
#undef ANKAH_STAT_SUM
#undef ANKAH_STAT_MAX
};

void ankah_text_init(ankah_text *text) {
    memset(text, 0, sizeof(*text));
}

void ankah_text_free(ankah_text *text) {
    free(text->data);
    ankah_text_init(text);
}

void ankah_text_append(ankah_text *text, const char *data, size_t size) {
    if (text->failed) return;
    if (size > ANKAH_TEXT_MAX - text->size) {
        text->failed = 1;
        return;
    }
    if (text->size + size > text->capacity) {
        size_t capacity = text->capacity ? text->capacity : 4096;
        char *grown;
        while (capacity < text->size + size) capacity *= 2;
        if (capacity > ANKAH_TEXT_MAX) capacity = ANKAH_TEXT_MAX;
        grown = (char *)realloc(text->data, capacity);
        if (!grown) {
            text->failed = 1;
            return;
        }
        text->data = grown;
        text->capacity = capacity;
    }
    memcpy(text->data + text->size, data, size);
    text->size += size;
}

void ankah_text_string(ankah_text *text, const char *string) {
    ankah_text_append(text, string, strlen(string));
}

void ankah_text_u64(ankah_text *text, uint64_t value) {
    char digits[20];
    size_t used = sizeof(digits);
    do {
        digits[--used] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    ankah_text_append(text, digits + used, sizeof(digits) - used);
}

static void merge(ankah_stat_record *into, const ankah_stat_record *from) {
    unsigned int i;
    for (i = 0; i < ANKAH_STAT_COUNT; ++i) {
        if (maxima[i]) {
            if (from->v[i] > into->v[i]) into->v[i] = from->v[i];
        } else into->v[i] += from->v[i];
    }
}

/* Returns the record displaced from a full ring, or NULL. */
static const ankah_stat_record *ring_push(stat_ring *ring, const ankah_stat_record *row,
                                          ankah_stat_record *displaced) {
    const ankah_stat_record *result = NULL;
    if (ring->count == ring->capacity) {
        *displaced = ring->rows[ring->head];
        result = displaced;
    } else ++ring->count;
    ring->rows[ring->head] = *row;
    ring->head = (ring->head + 1) % ring->capacity;
    return result;
}

static const ankah_stat_record *ring_age(const stat_ring *ring, size_t age) {
    if (age >= ring->count) return NULL;
    return &ring->rows[(ring->head + ring->capacity - 1 - age) % ring->capacity];
}

static void push_day(const ankah_stat_record *row) {
    ankah_stat_record displaced;
    if (ring_push(&days, row, &displaced)) {
        merge(&stats.evicted, &displaced);
        ++stats.evicted_days;
    }
}

void ankah_stats_init(uint64_t wall) {
    memset(&stats, 0, sizeof(stats));
    hours.head = hours.count = 0;
    days.head = days.count = 0;
    stats.enabled = 1;
    stats.epoch = wall;
    stats.hour_index = wall / 3600;
    stats.day_index = wall / 86400;
}

void ankah_stats_add(unsigned int field, uint64_t amount) {
    if (!stats.enabled || field >= ANKAH_STAT_COUNT) return;
    stats.cumulative.v[field] += amount;
    stats.hour.v[field] += amount;
    stats.day.v[field] += amount;
}

void ankah_stats_max(unsigned int field, uint64_t value) {
    if (!stats.enabled || field >= ANKAH_STAT_COUNT) return;
    if (value > stats.cumulative.v[field]) stats.cumulative.v[field] = value;
    if (value > stats.hour.v[field]) stats.hour.v[field] = value;
    if (value > stats.day.v[field]) stats.day.v[field] = value;
}

void ankah_stats_roll(uint64_t wall) {
    static const ankah_stat_record empty;
    uint64_t hour = wall / 3600, day = wall / 86400, gap, pushed;
    ankah_stat_record displaced;
    if (!stats.enabled) return;
    if (hour > stats.hour_index) {
        gap = hour - stats.hour_index - 1;
        ring_push(&hours, &stats.hour, &displaced);
        for (pushed = 0; pushed < gap && pushed < ANKAH_STAT_HOURS; ++pushed)
            ring_push(&hours, &empty, &displaced);
        memset(&stats.hour, 0, sizeof(stats.hour));
        stats.hour_index = hour;
    }
    if (day > stats.day_index) {
        gap = day - stats.day_index - 1;
        push_day(&stats.day);
        for (pushed = 0; pushed < gap && pushed < ANKAH_STAT_DAYS; ++pushed)
            push_day(&empty);
        /* Zero days beyond one full ring would only displace other zero days. */
        stats.evicted_days += gap - pushed;
        memset(&stats.day, 0, sizeof(stats.day));
        stats.day_index = day;
    }
}

#define SNAPSHOT_HEADER_SIZE 80U
#define SNAPSHOT_DIGEST_SIZE 32U
#define SNAPSHOT_VERSION 3U
#define SNAPSHOT_V1_FIELDS 32U
#define SNAPSHOT_V2_FIELDS 40U
#define SNAPSHOT_RECORD_SIZE (ANKAH_STAT_COUNT * 8U)
#define SNAPSHOT_MAX_SIZE \
    (SNAPSHOT_HEADER_SIZE + \
     (4U + ANKAH_STAT_HOURS + ANKAH_STAT_DAYS) * SNAPSHOT_RECORD_SIZE + \
     SNAPSHOT_DIGEST_SIZE)

typedef struct {
    stat_state state;
    size_t hour_count, day_count;
    uint64_t generation;
} decoded_snapshot;

static void put_u32(unsigned char **cursor, uint32_t value) {
    unsigned int i;
    for (i = 0; i < 4; ++i) {
        *(*cursor)++ = (unsigned char)value;
        value >>= 8;
    }
}

static void put_u64(unsigned char **cursor, uint64_t value) {
    unsigned int i;
    for (i = 0; i < 8; ++i) {
        *(*cursor)++ = (unsigned char)value;
        value >>= 8;
    }
}

static uint32_t get_u32(const unsigned char **cursor) {
    uint32_t value = 0;
    unsigned int i;
    for (i = 0; i < 4; ++i) value |= (uint32_t)*(*cursor)++ << (i * 8);
    return value;
}

static uint64_t get_u64(const unsigned char **cursor) {
    uint64_t value = 0;
    unsigned int i;
    for (i = 0; i < 8; ++i) value |= (uint64_t)*(*cursor)++ << (i * 8);
    return value;
}

static void put_record(unsigned char **cursor, const ankah_stat_record *record) {
    unsigned int field;
    for (field = 0; field < ANKAH_STAT_COUNT; ++field)
        put_u64(cursor, record->v[field]);
}

static void get_record(const unsigned char **cursor, ankah_stat_record *record,
                       unsigned int field_count) {
    unsigned int field;
    for (field = 0; field < field_count; ++field)
        record->v[field] = get_u64(cursor);
}

static int snapshot_path(const char *base, const char *suffix,
                         char out[ANKAH_STATS_PATH_MAX]) {
    int length = snprintf(out, ANKAH_STATS_PATH_MAX, "%s%s", base, suffix);
    return length > 0 && length < ANKAH_STATS_PATH_MAX ? 0 : -1;
}

static int totals_valid(const decoded_snapshot *snapshot) {
    unsigned int field;
    size_t row;
    uint64_t elapsed_days;
    if (snapshot->state.hour_index < snapshot->state.epoch / 3600 ||
        snapshot->state.day_index < snapshot->state.epoch / 86400)
        return 0;
    if (snapshot->hour_count !=
        (snapshot->state.hour_index - snapshot->state.epoch / 3600 < ANKAH_STAT_HOURS
             ? (size_t)(snapshot->state.hour_index - snapshot->state.epoch / 3600)
             : ANKAH_STAT_HOURS))
        return 0;
    elapsed_days = snapshot->state.day_index - snapshot->state.epoch / 86400;
    if (snapshot->state.evicted_days > elapsed_days ||
        (uint64_t)snapshot->day_count != elapsed_days - snapshot->state.evicted_days)
        return 0;
    for (field = 0; field < ANKAH_STAT_COUNT; ++field) {
        uint64_t total = snapshot->state.evicted.v[field];
        if (maxima[field]) {
            if (snapshot->state.day.v[field] > total)
                total = snapshot->state.day.v[field];
            for (row = 0; row < snapshot->day_count; ++row)
                if (snapshot->state.day_rows[row].v[field] > total)
                    total = snapshot->state.day_rows[row].v[field];
        } else {
            total += snapshot->state.day.v[field];
            for (row = 0; row < snapshot->day_count; ++row)
                total += snapshot->state.day_rows[row].v[field];
        }
        if (total != snapshot->state.cumulative.v[field]) return 0;
    }
    return 1;
}

static decoded_snapshot *decode_snapshot(const unsigned char *data, size_t size) {
    static const unsigned char magic[8] = {'A','N','K','H','S','T','A','T'};
    unsigned char digest[SNAPSHOT_DIGEST_SIZE];
    const unsigned char *cursor = data;
    decoded_snapshot *snapshot;
    uint32_t version, field_count, hour_count, day_count;
    size_t expected, row;
    if (size < SNAPSHOT_HEADER_SIZE + SNAPSHOT_DIGEST_SIZE ||
        memcmp(cursor, magic, sizeof(magic)) != 0) return NULL;
    cursor += sizeof(magic);
    version = get_u32(&cursor);
    field_count = get_u32(&cursor);
    if (!((version == 1 && field_count == SNAPSHOT_V1_FIELDS) ||
          (version == 2 && field_count == SNAPSHOT_V2_FIELDS) ||
          (version == SNAPSHOT_VERSION && field_count == ANKAH_STAT_COUNT)) ||
        get_u32(&cursor) != ANKAH_STAT_HOURS ||
        get_u32(&cursor) != ANKAH_STAT_DAYS) return NULL;
    snapshot = (decoded_snapshot *)calloc(1, sizeof(*snapshot));
    if (!snapshot) return NULL;
    snapshot->generation = get_u64(&cursor);
    (void)get_u64(&cursor); /* Saved wall time is informational in version 1. */
    snapshot->state.epoch = get_u64(&cursor);
    snapshot->state.hour_index = get_u64(&cursor);
    snapshot->state.day_index = get_u64(&cursor);
    snapshot->state.evicted_days = get_u64(&cursor);
    hour_count = get_u32(&cursor);
    day_count = get_u32(&cursor);
    if (!snapshot->generation || hour_count > ANKAH_STAT_HOURS ||
        day_count > ANKAH_STAT_DAYS) { free(snapshot); return NULL; }
    expected = SNAPSHOT_HEADER_SIZE +
               (4U + (size_t)hour_count + (size_t)day_count) * field_count * 8U +
               SNAPSHOT_DIGEST_SIZE;
    if (size != expected || ankah_sha256(data, size - SNAPSHOT_DIGEST_SIZE, digest) != 0 ||
        memcmp(digest, data + size - SNAPSHOT_DIGEST_SIZE, SNAPSHOT_DIGEST_SIZE) != 0) {
        free(snapshot);
        return NULL;
    }
    get_record(&cursor, &snapshot->state.cumulative, field_count);
    get_record(&cursor, &snapshot->state.hour, field_count);
    get_record(&cursor, &snapshot->state.day, field_count);
    get_record(&cursor, &snapshot->state.evicted, field_count);
    for (row = 0; row < hour_count; ++row)
        get_record(&cursor, &snapshot->state.hour_rows[row], field_count);
    for (row = 0; row < day_count; ++row)
        get_record(&cursor, &snapshot->state.day_rows[row], field_count);
    snapshot->hour_count = hour_count;
    snapshot->day_count = day_count;
    snapshot->state.enabled = 1;
    if (!totals_valid(snapshot)) { free(snapshot); return NULL; }
    return snapshot;
}

static unsigned char *encode_snapshot(uint64_t generation, uint64_t wall, size_t *size) {
    static const unsigned char magic[8] = {'A','N','K','H','S','T','A','T'};
    unsigned char digest[SNAPSHOT_DIGEST_SIZE], *data, *cursor;
    size_t age;
    *size = SNAPSHOT_HEADER_SIZE +
            (4U + hours.count + days.count) * SNAPSHOT_RECORD_SIZE +
            SNAPSHOT_DIGEST_SIZE;
    data = (unsigned char *)malloc(*size);
    if (!data) return NULL;
    cursor = data;
    memcpy(cursor, magic, sizeof(magic)); cursor += sizeof(magic);
    put_u32(&cursor, SNAPSHOT_VERSION);
    put_u32(&cursor, ANKAH_STAT_COUNT);
    put_u32(&cursor, ANKAH_STAT_HOURS);
    put_u32(&cursor, ANKAH_STAT_DAYS);
    put_u64(&cursor, generation);
    put_u64(&cursor, wall);
    put_u64(&cursor, stats.epoch);
    put_u64(&cursor, stats.hour_index);
    put_u64(&cursor, stats.day_index);
    put_u64(&cursor, stats.evicted_days);
    put_u32(&cursor, (uint32_t)hours.count);
    put_u32(&cursor, (uint32_t)days.count);
    put_record(&cursor, &stats.cumulative);
    put_record(&cursor, &stats.hour);
    put_record(&cursor, &stats.day);
    put_record(&cursor, &stats.evicted);
    for (age = hours.count; age > 0; --age)
        put_record(&cursor, ring_age(&hours, age - 1));
    for (age = days.count; age > 0; --age)
        put_record(&cursor, ring_age(&days, age - 1));
    if (ankah_sha256(data, *size - SNAPSHOT_DIGEST_SIZE, digest) != 0) {
        free(data);
        return NULL;
    }
    memcpy(cursor, digest, sizeof(digest));
    return data;
}

int ankah_stats_restore(const char *path, uint64_t wall) {
    decoded_snapshot *snapshots[2] = {NULL, NULL}, *chosen = NULL;
    int result = 0, slot;
    snapshot_generation = 0;
    for (slot = 0; slot < 2; ++slot) {
        char candidate_path[ANKAH_STATS_PATH_MAX];
        unsigned char *data = NULL;
        size_t size = 0;
        int read_result;
        if (snapshot_path(path, slot ? ".1" : ".0", candidate_path) != 0) {
            result |= ANKAH_STATS_DEGRADED;
            continue;
        }
        read_result = ankah_file_read_optional(candidate_path, SNAPSHOT_MAX_SIZE, 1,
                                               &data, &size);
        if (read_result == 0) {
            snapshots[slot] = decode_snapshot(data, size);
            if (!snapshots[slot]) result |= ANKAH_STATS_DEGRADED;
            free(data);
        } else if (read_result < 0) result |= ANKAH_STATS_DEGRADED;
    }
    if (snapshots[0] && snapshots[1])
        chosen = snapshots[snapshots[1]->generation > snapshots[0]->generation ? 1 : 0];
    else chosen = snapshots[0] ? snapshots[0] : snapshots[1];
    if (chosen) {
        stats = chosen->state;
        hours.head = chosen->hour_count % ANKAH_STAT_HOURS;
        hours.count = chosen->hour_count;
        days.head = chosen->day_count % ANKAH_STAT_DAYS;
        days.count = chosen->day_count;
        snapshot_generation = chosen->generation;
        result |= ANKAH_STATS_RESTORED;
        ankah_stats_roll(wall);
    } else ankah_stats_init(wall);
    free(snapshots[0]);
    free(snapshots[1]);
    return result;
}

int ankah_stats_save(const char *path, uint64_t wall) {
    unsigned char *data;
    char temp_path[ANKAH_STATS_PATH_MAX], target_path[ANKAH_STATS_PATH_MAX];
    uint64_t generation;
    size_t size;
    int result;
    if (!stats.enabled || snapshot_generation == UINT64_MAX) return -1;
    generation = snapshot_generation + 1;
    if (snapshot_path(path, ".tmp", temp_path) != 0 ||
        snapshot_path(path, generation & 1 ? ".1" : ".0", target_path) != 0)
        return -1;
    data = encode_snapshot(generation, wall, &size);
    if (!data) return -1;
    result = ankah_file_replace(temp_path, target_path, data, size);
    free(data);
    if (result == 0) snapshot_generation = generation;
    return result;
}

const char *ankah_stat_name(unsigned int field) {
    return field < ANKAH_STAT_COUNT ? names[field] : NULL;
}

int ankah_stat_is_max(unsigned int field) {
    return field < ANKAH_STAT_COUNT && maxima[field];
}

uint64_t ankah_stats_epoch(void) { return stats.epoch; }
uint64_t ankah_stats_hour_index(void) { return stats.hour_index; }
uint64_t ankah_stats_day_index(void) { return stats.day_index; }
uint64_t ankah_stats_evicted_days(void) { return stats.evicted_days; }
size_t ankah_stats_hour_count(void) { return hours.count; }
size_t ankah_stats_day_count(void) { return days.count; }
const ankah_stat_record *ankah_stats_cumulative(void) { return &stats.cumulative; }
const ankah_stat_record *ankah_stats_current_hour(void) { return &stats.hour; }
const ankah_stat_record *ankah_stats_current_day(void) { return &stats.day; }
const ankah_stat_record *ankah_stats_evicted(void) { return &stats.evicted; }
const ankah_stat_record *ankah_stats_hour(size_t age) { return ring_age(&hours, age); }
const ankah_stat_record *ankah_stats_day(size_t age) { return ring_age(&days, age); }

static void write_row(ankah_text *out, const ankah_stat_record *row) {
    unsigned int i;
    ankah_text_string(out, "[");
    for (i = 0; i < ANKAH_STAT_COUNT; ++i) {
        if (i) ankah_text_string(out, ",");
        ankah_text_u64(out, row->v[i]);
    }
    ankah_text_string(out, "]");
}

static void write_member(ankah_text *out, const char *name, uint64_t value) {
    ankah_text_string(out, "\"");
    ankah_text_string(out, name);
    ankah_text_string(out, "\":");
    ankah_text_u64(out, value);
}

/* The most recent `wanted` completed buckets, oldest first. */
static void write_series(ankah_text *out, const char *name, const stat_ring *ring,
                         uint64_t current_index, size_t wanted) {
    size_t age;
    if (wanted > ring->count) wanted = ring->count;
    ankah_text_string(out, "\"");
    ankah_text_string(out, name);
    ankah_text_string(out, "\":{");
    write_member(out, "first", current_index - wanted);
    ankah_text_string(out, ",\"rows\":[");
    for (age = wanted; age > 0; --age) {
        if (age != wanted) ankah_text_string(out, ",");
        write_row(out, ring_age(ring, age - 1));
    }
    ankah_text_string(out, "]}");
}

void ankah_stats_write_schema(ankah_text *out) {
    unsigned int i;
    ankah_text_string(out, "\"fields\":[");
    for (i = 0; i < ANKAH_STAT_COUNT; ++i) {
        if (i) ankah_text_string(out, ",");
        ankah_text_string(out, "\"");
        ankah_text_string(out, names[i]);
        ankah_text_string(out, "\"");
    }
    ankah_text_string(out, "],\"kinds\":[");
    for (i = 0; i < ANKAH_STAT_COUNT; ++i) {
        if (i) ankah_text_string(out, ",");
        ankah_text_string(out, maxima[i] ? "\"max\"" : "\"sum\"");
    }
    ankah_text_string(out, "],");
    write_member(out, "hour_seconds", 3600);
    ankah_text_string(out, ",");
    write_member(out, "day_seconds", 86400);
    ankah_text_string(out, ",");
    write_member(out, "hour_capacity", ANKAH_STAT_HOURS);
    ankah_text_string(out, ",");
    write_member(out, "day_capacity", ANKAH_STAT_DAYS);
}

static void write_indices(ankah_text *out) {
    write_member(out, "epoch", stats.epoch);
    ankah_text_string(out, ",");
    write_member(out, "hour_index", stats.hour_index);
    ankah_text_string(out, ",");
    write_member(out, "day_index", stats.day_index);
}

void ankah_stats_write_live(ankah_text *out) {
    write_indices(out);
    ankah_text_string(out, ",\"cumulative\":");
    write_row(out, &stats.cumulative);
    ankah_text_string(out, ",\"current_hour\":");
    write_row(out, &stats.hour);
    ankah_text_string(out, ",\"current_day\":");
    write_row(out, &stats.day);
    ankah_text_string(out, ",");
    write_series(out, "recent_hours", &hours, stats.hour_index, 2);
    ankah_text_string(out, ",");
    write_series(out, "recent_days", &days, stats.day_index, 1);
}

void ankah_stats_write_history(ankah_text *out, size_t hour_rows, size_t day_rows) {
    write_indices(out);
    ankah_text_string(out, ",");
    write_series(out, "hours", &hours, stats.hour_index, hour_rows);
    ankah_text_string(out, ",");
    write_series(out, "days", &days, stats.day_index, day_rows);
    ankah_text_string(out, ",\"evicted\":");
    write_row(out, &stats.evicted);
    ankah_text_string(out, ",");
    write_member(out, "evicted_days", stats.evicted_days);
}

static void csv_time(ankah_text *out, uint64_t seconds) {
    char value[32];
    time_t stamp = (time_t)seconds;
    struct tm *utc;
    if (stamp < 0 || (uint64_t)stamp != seconds || !(utc = gmtime(&stamp)) ||
        !strftime(value, sizeof(value), "%Y-%m-%dT%H:%M:%SZ", utc)) {
        out->failed = 1;
        return;
    }
    ankah_text_string(out, value);
}

static void csv_row(ankah_text *out, const char *type, uint64_t start,
                    uint64_t end, int partial, uint64_t buckets,
                    const ankah_stat_record *record) {
    unsigned int field;
    ankah_text_string(out, type);
    ankah_text_string(out, ",");
    csv_time(out, start);
    ankah_text_string(out, ",");
    csv_time(out, end);
    ankah_text_string(out, partial ? ",1," : ",0,");
    ankah_text_u64(out, buckets);
    for (field = 0; field < ANKAH_STAT_COUNT; ++field) {
        ankah_text_string(out, ",");
        ankah_text_u64(out, record->v[field]);
    }
    ankah_text_string(out, "\r\n");
}

void ankah_stats_write_csv(ankah_text *out, uint64_t wall) {
    uint64_t first_day, first_hour, hour_cutoff, index, start;
    unsigned int field;
    ankah_stats_roll(wall);
    ankah_text_append(out, "\xef\xbb\xbf", 3);
    ankah_text_string(out,
        "record_type,period_start_utc,period_end_utc,partial,bucket_count");
    for (field = 0; field < ANKAH_STAT_COUNT; ++field) {
        ankah_text_string(out, ",");
        ankah_text_string(out, names[field]);
    }
    ankah_text_string(out, "\r\n");

    first_day = stats.day_index - days.count;
    if (stats.evicted_days)
        csv_row(out, "aggregate_days", stats.epoch, first_day * UINT64_C(86400),
                0, stats.evicted_days, &stats.evicted);

    first_hour = stats.hour_index - hours.count;
    hour_cutoff = first_hour;
    if (first_hour % 24 && first_hour / 24 >= first_day &&
        first_hour / 24 < stats.day_index)
        hour_cutoff = (first_hour / 24 + 1) * 24;

    for (index = first_day; index < stats.day_index; ++index) {
        uint64_t end = (index + 1) * UINT64_C(86400);
        size_t age;
        if (end > hour_cutoff * UINT64_C(3600)) break;
        age = (size_t)(stats.day_index - 1 - index);
        start = index * UINT64_C(86400);
        if (start < stats.epoch) start = stats.epoch;
        csv_row(out, "day", start, end, 0, 1, ring_age(&days, age));
    }
    for (index = hour_cutoff; index < stats.hour_index; ++index) {
        size_t age = (size_t)(stats.hour_index - 1 - index);
        start = index * UINT64_C(3600);
        if (start < stats.epoch) start = stats.epoch;
        csv_row(out, "hour", start, (index + 1) * UINT64_C(3600),
                0, 1, ring_age(&hours, age));
    }
    start = stats.hour_index * UINT64_C(3600);
    if (start < stats.epoch) start = stats.epoch;
    csv_row(out, "current_hour", start, wall < start ? start : wall,
            1, 1, &stats.hour);
}
