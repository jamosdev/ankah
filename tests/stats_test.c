#include "ankah/stats.h"
#include "ankah/sha256.h"
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

static size_t line_count(const ankah_text *text, const char *prefix) {
    size_t length = strlen(prefix), offset = 0, count = 0;
    while (offset + length <= text->size) {
        if ((offset == 0 || text->data[offset - 1] == '\n') &&
            memcmp(text->data + offset, prefix, length) == 0) ++count;
        while (offset < text->size && text->data[offset++] != '\n') {}
    }
    return count;
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
                       sizeof(ankah_stat_record) == ANKAH_STAT_SLOTS * sizeof(uint64_t),
                       "record size");

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
    ankah_text text;
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
    ankah_text_init(&text);
    ankah_stats_write_csv(&text, start + (3 * ANKAH_STAT_DAYS + 5) * DAY + 60);
    failures += expect(line_count(&text, "aggregate_days,") == 1,
                       "CSV includes evicted day aggregate");
    ankah_text_free(&text);
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
                       contains(&text, "\"challenge_session_rejected\"],\"kinds\":[\"sum\",") &&
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

    ankah_stats_write_csv(&text, start + 3 * HOUR + 60);
    failures += expect(text.size > 3 &&
                       memcmp(text.data, "\xef\xbb\xbf", 3) == 0 &&
                       contains(&text, "record_type,period_start_utc,period_end_utc,") &&
                       line_count(&text, "hour,") == 3 &&
                       line_count(&text, "current_hour,") == 1 &&
                       contains(&text, "current_hour,2024-") &&
                       text.data[text.size - 2] == '\r' && text.data[text.size - 1] == '\n',
                       "CSV writer emits hourly timeline");
    ankah_text_free(&text);

    ankah_stats_init(start + 14 * HOUR);
    for (size_t hour = 0; hour < ANKAH_STAT_HOURS + 24; ++hour) {
        ankah_stats_add(ANKAH_STAT_requests, 1);
        ankah_stats_roll(start + 14 * HOUR + (hour + 1) * HOUR);
    }
    ankah_stats_write_csv(&text, start + 14 * HOUR +
                          (ANKAH_STAT_HOURS + 24) * HOUR + 60);
    failures += expect(line_count(&text, "day,") == 2 &&
                       line_count(&text, "hour,") == ANKAH_STAT_HOURS - 10 &&
                       line_count(&text, "current_hour,") == 1,
                       "CSV switches from days to hours without overlap");
    ankah_text_free(&text);

    ankah_stats_init(start);
    for (size_t hour = 0; hour < ANKAH_STAT_HOURS + 24; ++hour)
        ankah_stats_roll(start + (hour + 1) * HOUR);
    ankah_stats_write_csv(&text, start + (ANKAH_STAT_HOURS + 24) * HOUR + 60);
    failures += expect(line_count(&text, "day,") == 1 &&
                       line_count(&text, "hour,") == ANKAH_STAT_HOURS,
                       "CSV preserves hours at a midnight boundary");
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

static unsigned int little_u32(const unsigned char *p) {
    return (unsigned int)p[0] | (unsigned int)p[1] << 8 |
           (unsigned int)p[2] << 16 | (unsigned int)p[3] << 24;
}

static int make_older_snapshot(const char *source_path, const char *target_path,
                               unsigned int version, unsigned int fields) {
    FILE *source = NULL, *target = NULL;
    unsigned char *input = NULL, *output = NULL;
    unsigned char digest[32];
    long input_size;
    size_t records, output_size, row;
    int result = -1;
    source = fopen(source_path, "rb");
    if (!source || fseek(source, 0, SEEK_END) != 0 ||
        (input_size = ftell(source)) < 112 || fseek(source, 0, SEEK_SET) != 0) goto done;
    input = malloc((size_t)input_size);
    if (!input || fread(input, 1, (size_t)input_size, source) != (size_t)input_size ||
        little_u32(input + 8) != 3 ||
        little_u32(input + 12) != ANKAH_STAT_COUNT) goto done;
    records = 4U + little_u32(input + 72) + little_u32(input + 76);
    if ((size_t)input_size != 80U + records * ANKAH_STAT_COUNT * 8U + 32U) goto done;
    output_size = 80U + records * fields * 8U + 32U;
    output = calloc(1, output_size);
    if (!output) goto done;
    memcpy(output, input, 80);
    output[8] = (unsigned char)version;
    output[9] = output[10] = output[11] = 0;
    output[12] = (unsigned char)fields;
    output[13] = output[14] = output[15] = 0;
    for (row = 0; row < records; ++row)
        memcpy(output + 80U + row * fields * 8U,
               input + 80U + row * ANKAH_STAT_COUNT * 8U, fields * 8U);
    if (ankah_sha256(output, output_size - 32U, digest) != 0) goto done;
    memcpy(output + output_size - 32U, digest, 32U);
    target = fopen(target_path, "wb");
    if (!target || fwrite(output, 1, output_size, target) != output_size ||
        fclose(target) != 0) {
        target = NULL;
        goto done;
    }
    target = NULL;
    result = 0;
done:
    if (source) fclose(source);
    if (target) fclose(target);
    free(input);
    free(output);
    return result;
}

static int persistence_test(void) {
    static const char base[] = "ankah-stats-test-state";
    static const char v1_base[] = "ankah-stats-test-v1";
    static const char v2_base[] = "ankah-stats-test-v2";
    const uint64_t start = 30000 * DAY + 5 * HOUR;
    int failures = 0, restored;
    remove_snapshots(base);
    remove_snapshots(v1_base);
    remove_snapshots(v2_base);

    restored = ankah_stats_restore(base, start);
    failures += expect(restored == 0 && ankah_stats_epoch() == start,
                       "missing snapshots start empty");
    ankah_stats_add(ANKAH_STAT_requests, 12);
    ankah_stats_roll(start + HOUR);
    ankah_stats_add(ANKAH_STAT_requests, 3);
    failures += expect(ankah_stats_save(base, start + HOUR) == 0,
                       "first snapshot saves");
    failures += expect(make_older_snapshot("ankah-stats-test-state.1",
                                          "ankah-stats-test-v1.1", 1, 32) == 0,
                       "version 1 snapshot fixture converts");
    failures += expect(make_older_snapshot("ankah-stats-test-state.1",
                                          "ankah-stats-test-v2.1", 2, 40) == 0,
                       "version 2 snapshot fixture converts");
    ankah_stats_init(start + 10);
    restored = ankah_stats_restore(v1_base, start + HOUR);
    failures += expect((restored & ANKAH_STATS_RESTORED) &&
                       !(restored & ANKAH_STATS_DEGRADED) &&
                       ankah_stats_cumulative()->v[ANKAH_STAT_requests] == 15 &&
                       ankah_stats_cumulative()->v[ANKAH_STAT_throttled_static_requests] == 0,
                       "version 1 snapshot migrates with new fields zeroed");
    restored = ankah_stats_restore(v2_base, start + HOUR);
    failures += expect((restored & ANKAH_STATS_RESTORED) &&
                       !(restored & ANKAH_STATS_DEGRADED) &&
                       ankah_stats_cumulative()->v[ANKAH_STAT_requests] == 15 &&
                       ankah_stats_cumulative()->v[ANKAH_STAT_rate_limited_anonymous] == 0,
                       "version 2 snapshot migrates with new fields zeroed");
    restored = ankah_stats_restore(base, start + HOUR);
    failures += expect((restored & ANKAH_STATS_RESTORED) &&
                       !(restored & ANKAH_STATS_DEGRADED),
                       "current snapshot restores after migration test");
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
    remove_snapshots(v1_base);
    remove_snapshots(v2_base);
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
