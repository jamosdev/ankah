#include "ankah/stats.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOUR UINT64_C(3600)
#define DAY UINT64_C(86400)

static int expect(int truth, const char *name) {
    if (!truth) fprintf(stderr, "FAIL: %s\n", name);
    return truth ? 0 : 1;
}

static uint64_t random_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t next_random(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

static int is_zero(const ankah_stat_record *row) {
    unsigned int i;
    for (i = 0; i < ANKAH_STAT_COUNT; ++i) if (row->v[i]) return 0;
    return 1;
}

/* evicted + every retained day + the current day equals cumulative. */
static int sums_balance(void) {
    unsigned int field;
    size_t age;
    for (field = 0; field < ANKAH_STAT_COUNT; ++field) {
        uint64_t total;
        if (ankah_stat_is_max(field)) continue;
        total = ankah_stats_evicted()->v[field] + ankah_stats_current_day()->v[field];
        for (age = 0; age < ankah_stats_day_count(); ++age)
            total += ankah_stats_day(age)->v[field];
        if (total != ankah_stats_cumulative()->v[field]) return 0;
    }
    return 1;
}

static int contains(const ankah_text *text, const char *needle) {
    size_t length = strlen(needle), i;
    if (text->failed || length > text->size) return 0;
    for (i = 0; i + length <= text->size; ++i)
        if (memcmp(text->data + i, needle, length) == 0) return 1;
    return 0;
}

static int text_test(void) {
    int failures = 0;
    ankah_text text;
    ankah_text_init(&text);
    ankah_text_u64(&text, 0);
    ankah_text_string(&text, ",");
    ankah_text_u64(&text, UINT64_MAX);
    failures += expect(!text.failed && text.size == 22 &&
                       memcmp(text.data, "0,18446744073709551615", 22) == 0,
                       "decimal encoding");
    ankah_text_free(&text);
    failures += expect(text.data == NULL && text.size == 0, "text free resets");
    return failures;
}

static int disabled_test(void) {
    int failures = 0;
    ankah_stats_add(ANKAH_STAT_requests, 5);
    ankah_stats_max(ANKAH_STAT_peak_connections, 9);
    ankah_stats_roll(10 * DAY);
    failures += expect(is_zero(ankah_stats_cumulative()), "no counting before init");
    failures += expect(ankah_stats_hour_count() == 0 && ankah_stats_day_count() == 0,
                       "no rolling before init");
    return failures;
}

static int roll_test(void) {
    int failures = 0;
    const uint64_t start = 1000 * DAY + 14 * HOUR + 37 * 60;
    const ankah_stat_record *row;
    size_t age;
    ankah_stats_init(start);
    failures += expect(ankah_stats_epoch() == start, "epoch is start time");
    failures += expect(ankah_stats_hour_index() == start / HOUR &&
                       ankah_stats_day_index() == start / DAY, "wall aligned indices");

    ankah_stats_add(ANKAH_STAT_requests, 3);
    ankah_stats_add(ANKAH_STAT_requests, 4);
    ankah_stats_max(ANKAH_STAT_peak_connections, 5);
    ankah_stats_max(ANKAH_STAT_peak_connections, 2);
    failures += expect(ankah_stats_cumulative()->v[ANKAH_STAT_requests] == 7 &&
                       ankah_stats_current_hour()->v[ANKAH_STAT_requests] == 7 &&
                       ankah_stats_current_day()->v[ANKAH_STAT_requests] == 7,
                       "sum field reaches all accumulators");
    failures += expect(ankah_stats_current_hour()->v[ANKAH_STAT_peak_connections] == 5,
                       "max field keeps the peak");
    failures += expect(ankah_stat_is_max(ANKAH_STAT_peak_connections) &&
                       !ankah_stat_is_max(ANKAH_STAT_requests), "field kinds");
    failures += expect(strcmp(ankah_stat_name(ANKAH_STAT_client_bytes_in),
                              "client_bytes_in") == 0 &&
                       ankah_stat_name(ANKAH_STAT_COUNT) == NULL, "field names");
    failures += expect(ANKAH_STAT_COUNT <= ANKAH_STAT_SLOTS &&
                       sizeof(ankah_stat_record) == 256, "record size");

    ankah_stats_roll(start + 60);
    failures += expect(ankah_stats_hour_count() == 0 &&
                       ankah_stats_current_hour()->v[ANKAH_STAT_requests] == 7,
                       "same hour roll is a no-op");

    ankah_stats_roll(start - 3 * HOUR);
    failures += expect(ankah_stats_hour_index() == start / HOUR &&
                       ankah_stats_hour_count() == 0, "backward step is ignored");

    ankah_stats_roll(start + HOUR);
    row = ankah_stats_hour(0);
    failures += expect(ankah_stats_hour_count() == 1 && row &&
                       row->v[ANKAH_STAT_requests] == 7 &&
                       row->v[ANKAH_STAT_peak_connections] == 5,
                       "completed hour enters the ring");
    failures += expect(is_zero(ankah_stats_current_hour()), "new hour starts empty");
    failures += expect(ankah_stats_current_day()->v[ANKAH_STAT_requests] == 7,
                       "day continues across hours");

    ankah_stats_add(ANKAH_STAT_requests, 1);
    ankah_stats_roll(start + 5 * HOUR);
    failures += expect(ankah_stats_hour_count() == 5, "gap hours are filled");
    failures += expect(ankah_stats_hour(0) && is_zero(ankah_stats_hour(0)) &&
                       ankah_stats_hour(2) && is_zero(ankah_stats_hour(2)) &&
                       ankah_stats_hour(3) &&
                       ankah_stats_hour(3)->v[ANKAH_STAT_requests] == 1 &&
                       ankah_stats_hour(4)->v[ANKAH_STAT_requests] == 7 &&
                       ankah_stats_hour(5) == NULL, "gap hours are zero");

    ankah_stats_roll(start + DAY);
    failures += expect(ankah_stats_day_count() == 1 && ankah_stats_day(0) &&
                       ankah_stats_day(0)->v[ANKAH_STAT_requests] == 8,
                       "completed day enters the ring");
    failures += expect(sums_balance(), "balance after a day");

    ankah_stats_roll(start + DAY + (ANKAH_STAT_HOURS + 10) * HOUR);
    failures += expect(ankah_stats_hour_count() == ANKAH_STAT_HOURS, "hour ring is bounded");
    for (age = 0; age < ANKAH_STAT_HOURS; ++age)
        if (!is_zero(ankah_stats_hour(age))) break;
    failures += expect(age == ANKAH_STAT_HOURS, "old hours are discarded");
    failures += expect(ankah_stats_evicted_days() == 0, "hour eviction leaves days alone");
    failures += expect(sums_balance(), "balance after hour wrap");
    return failures;
}

static int eviction_test(void) {
    int failures = 0;
    const uint64_t start = 20000 * DAY;
    uint64_t day;
    ankah_stats_init(start);
    ankah_stats_add(ANKAH_STAT_client_bytes_in, 100);
    ankah_stats_max(ANKAH_STAT_peak_sessions, 40);
    ankah_stats_roll(start + DAY);
    ankah_stats_add(ANKAH_STAT_client_bytes_in, 50);
    ankah_stats_max(ANKAH_STAT_peak_sessions, 10);
    for (day = 2; day <= ANKAH_STAT_DAYS + 2; ++day) ankah_stats_roll(start + day * DAY);
    failures += expect(ankah_stats_day_count() == ANKAH_STAT_DAYS, "day ring is bounded");
    failures += expect(ankah_stats_evicted_days() == 2, "two days evicted");
    failures += expect(ankah_stats_evicted()->v[ANKAH_STAT_client_bytes_in] == 150,
                       "evicted sums merge by addition");
    failures += expect(ankah_stats_evicted()->v[ANKAH_STAT_peak_sessions] == 40,
                       "evicted maxima merge by maximum");
    failures += expect(sums_balance(), "balance after day wrap");

    ankah_stats_add(ANKAH_STAT_client_bytes_out, 9);
    ankah_stats_roll(start + (3 * ANKAH_STAT_DAYS + 5) * DAY);
    failures += expect(ankah_stats_day_count() == ANKAH_STAT_DAYS, "long jump stays bounded");
    failures += expect(ankah_stats_evicted_days() == 3 * ANKAH_STAT_DAYS + 5 -
                       ANKAH_STAT_DAYS, "long jump counts every evicted day");
    failures += expect(ankah_stats_evicted()->v[ANKAH_STAT_client_bytes_out] == 9,
                       "long jump keeps the last live day");
    failures += expect(sums_balance(), "balance after long jump");
    return failures;
}

static int random_test(void) {
    int failures = 0, balanced = 1;
    const uint64_t start = 17000 * DAY + 5 * HOUR;
    uint64_t wall = start, step;
    ankah_stats_init(start);
    for (step = 0; wall < start + 5000 * DAY; ++step) {
        unsigned int field = (unsigned int)(next_random() % ANKAH_STAT_COUNT);
        uint64_t amount = next_random() % 100000;
        if (ankah_stat_is_max(field)) ankah_stats_max(field, amount);
        else ankah_stats_add(field, amount);
        if (next_random() % 4 == 0) {
            wall += next_random() % (2 * DAY);
            if (next_random() % 50 == 0) wall -= next_random() % HOUR;
            ankah_stats_roll(wall);
        }
        if (step % 997 == 0 && !sums_balance()) balanced = 0;
    }
    failures += expect(balanced && sums_balance(), "balance across 5000 random days");
    failures += expect(ankah_stats_evicted_days() > 0 &&
                       ankah_stats_evicted_days() + ankah_stats_day_count() ==
                       ankah_stats_day_index() - start / DAY,
                       "every completed day is retained or evicted");
    return failures;
}

static int writer_test(void) {
    int failures = 0;
    const uint64_t start = 20000 * DAY;
    ankah_text text;
    ankah_stats_init(start);
    ankah_stats_add(ANKAH_STAT_requests, 12);
    ankah_stats_roll(start + HOUR);
    ankah_stats_roll(start + 2 * HOUR);
    ankah_stats_roll(start + 3 * HOUR);

    ankah_text_init(&text);
    ankah_stats_write_schema(&text);
    failures += expect(contains(&text, "\"fields\":[\"client_bytes_in\",") &&
                       contains(&text, "\"peak_pending_bytes\"],\"kinds\":[\"sum\",") &&
                       contains(&text, "\"day_capacity\":4096"), "schema members");
    ankah_text_free(&text);

    ankah_stats_write_live(&text);
    failures += expect(contains(&text, "\"recent_hours\":{\"first\":480001,\"rows\":[[") &&
                       contains(&text, "\"recent_days\":{\"first\":20000,\"rows\":[]}") &&
                       contains(&text, "\"hour_index\":480003"), "live members");
    ankah_text_free(&text);

    ankah_stats_write_history(&text, 100, 100);
    failures += expect(contains(&text, "\"hours\":{\"first\":480000,\"rows\":[[") &&
                       contains(&text, "\"evicted_days\":0"), "history members");
    ankah_text_free(&text);

    ankah_stats_init(start + 7);
    failures += expect(is_zero(ankah_stats_cumulative()) && ankah_stats_hour_count() == 0 &&
                       ankah_stats_epoch() == start + 7, "reset clears everything");
    return failures;
}

static void remove_snapshots(const char *base) {
    char path[128];
    snprintf(path, sizeof(path), "%s.0", base); remove(path);
    snprintf(path, sizeof(path), "%s.1", base); remove(path);
    snprintf(path, sizeof(path), "%s.tmp", base); remove(path);
}

static int damage_file(const char *path) {
    FILE *file = fopen(path, "r+b");
    int byte, result = 0;
    if (!file) return -1;
    byte = fgetc(file);
    if (byte == EOF || fseek(file, 0, SEEK_SET) != 0 ||
        fputc(byte ^ 0xff, file) == EOF) result = -1;
    if (fclose(file) != 0) result = -1;
    return result;
}

static int persistence_test(void) {
    static const char base[] = "ankah-stats-test-state";
    const uint64_t start = 30000 * DAY + 5 * HOUR;
    int failures = 0, restored;
    remove_snapshots(base);

    restored = ankah_stats_restore(base, start);
    failures += expect(restored == 0 && ankah_stats_epoch() == start,
                       "missing snapshots start empty");
    ankah_stats_add(ANKAH_STAT_requests, 12);
    ankah_stats_roll(start + HOUR);
    ankah_stats_add(ANKAH_STAT_requests, 3);
    failures += expect(ankah_stats_save(base, start + HOUR) == 0,
                       "first snapshot saves");
    ankah_stats_add(ANKAH_STAT_requests, 5);
    failures += expect(ankah_stats_save(base, start + HOUR) == 0,
                       "second snapshot saves");

    ankah_stats_init(start + 10);
    restored = ankah_stats_restore(base, start + 2 * HOUR);
    failures += expect((restored & ANKAH_STATS_RESTORED) &&
                       !(restored & ANKAH_STATS_DEGRADED) &&
                       ankah_stats_cumulative()->v[ANKAH_STAT_requests] == 20 &&
                       ankah_stats_hour_index() == start / HOUR + 2,
                       "newest snapshot restores and rolls forward");

    failures += expect(damage_file("ankah-stats-test-state.0") == 0,
                       "newest snapshot can be damaged");
    restored = ankah_stats_restore(base, start + HOUR);
    failures += expect((restored & ANKAH_STATS_RESTORED) &&
                       (restored & ANKAH_STATS_DEGRADED) &&
                       ankah_stats_cumulative()->v[ANKAH_STAT_requests] == 15,
                       "corrupt newest snapshot falls back");

    failures += expect(damage_file("ankah-stats-test-state.1") == 0,
                       "older snapshot can be damaged");
    restored = ankah_stats_restore(base, start + 3 * HOUR);
    failures += expect(!(restored & ANKAH_STATS_RESTORED) &&
                       (restored & ANKAH_STATS_DEGRADED) &&
                       ankah_stats_epoch() == start + 3 * HOUR &&
                       is_zero(ankah_stats_cumulative()),
                       "two corrupt snapshots degrade to empty");

    failures += expect(ankah_stats_save("missing-directory/ankah", start) != 0,
                       "write failure is reported");
    remove_snapshots(base);
    return failures;
}

int main(void) {
    int failures = 0;
    failures += text_test();
    failures += disabled_test();
    failures += roll_test();
    failures += eviction_test();
    failures += random_test();
    failures += writer_test();
    failures += persistence_test();
    return failures ? 1 : 0;
}
