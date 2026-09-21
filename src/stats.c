#include "ankah/stats.h"

#include <stdlib.h>
#include <string.h>

/* Fails to compile when the field list outgrows the record. */
typedef char ankah_stat_fields_fit[ANKAH_STAT_COUNT <= ANKAH_STAT_SLOTS ? 1 : -1];

typedef struct {
    ankah_stat_record *rows;
    size_t capacity, head, count;
} stat_ring;

static struct {
    int enabled;
    uint64_t epoch, hour_index, day_index, evicted_days;
    ankah_stat_record cumulative, hour, day, evicted;
    ankah_stat_record hour_rows[ANKAH_STAT_HOURS];
    ankah_stat_record day_rows[ANKAH_STAT_DAYS];
} stats;

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
