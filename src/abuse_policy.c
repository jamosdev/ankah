#include "abuse_policy.h"
#include <string.h>
#include <stdlib.h>

#define ANKAH_ABUSE_CAPACITY 4096
typedef struct {
    char ip[64];
    uint64_t seen_ns, signal_ns;
    uint64_t times[ANKAH_ABUSE_REASONS][40];
    unsigned int count[ANKAH_ABUSE_REASONS];
    unsigned char path_hashes[40];
    uint64_t paths[4];
    int signaled;
} ankah_abuse_entry;
struct ankah_abuse_policy {
    ankah_abuse_entry entries[ANKAH_ABUSE_CAPACITY];
    ankah_abuse_profile profile;
    uint64_t signals[ANKAH_ABUSE_REASONS];
};
ankah_abuse_policy *ankah_abuse_create(void) {
    ankah_abuse_policy *policy = calloc(1, sizeof(*policy));
    if (policy) policy->profile = ANKAH_ABUSE_CONSERVATIVE;
    return policy;
}
void ankah_abuse_destroy(ankah_abuse_policy *policy) { free(policy); }
void ankah_abuse_set_profile(ankah_abuse_policy *policy, ankah_abuse_profile profile) {
    if (policy) policy->profile = profile;
}
uint64_t ankah_abuse_signal_count(const ankah_abuse_policy *policy, ankah_abuse_event event) {
    return policy && event < ANKAH_ABUSE_REASONS ? policy->signals[event] : 0;
}
#define SECOND UINT64_C(1000000000)
static unsigned int path_bits(const uint64_t paths[4]) {
    unsigned int count = 0, i;
    for (i = 0; i < 4; ++i) {
        uint64_t value = paths[i];
        while (value) { value &= value - 1; ++count; }
    }
    return count;
}
static unsigned int hash_path(const char *path) {
    uint32_t hash = UINT32_C(2166136261);
    while (*path && *path != '?') {
        hash ^= (unsigned char)*path++;
        hash *= UINT32_C(16777619);
    }
    hash ^= hash >> 16;
    return hash & 255U;
}
int ankah_abuse_record(ankah_abuse_policy *policy, const char *ip,
                       ankah_abuse_event event, const char *path, uint64_t now_ns) {
    static const unsigned int conservative[] = {8, 8, 40, 3};
    static const unsigned int strict[] = {4, 4, 20, 2};
    static const uint64_t windows[] = {60 * SECOND, 60 * SECOND, 30 * SECOND, 600 * SECOND};
    const unsigned int *limits;
    ankah_abuse_entry *entry = NULL, *oldest;
    unsigned int i, kept;
    if (!policy || policy->profile == ANKAH_ABUSE_OFF || !ip || !*ip ||
        strlen(ip) >= sizeof(oldest->ip) || event >= ANKAH_ABUSE_REASONS) return 0;
    oldest = &policy->entries[0];
    limits = policy->profile == ANKAH_ABUSE_STRICT ? strict : conservative;
    for (i = 0; i < ANKAH_ABUSE_CAPACITY; ++i) {
        ankah_abuse_entry *candidate = &policy->entries[i];
        if (strcmp(candidate->ip, ip) == 0) { entry = candidate; break; }
        if (!candidate->ip[0]) oldest = candidate;
        else if (oldest->ip[0] && candidate->seen_ns < oldest->seen_ns) oldest = candidate;
    }
    if (!entry) {
        entry = oldest;
        memset(entry, 0, sizeof(*entry));
        strcpy(entry->ip, ip);
    }
    entry->seen_ns = now_ns;
    if (event == ANKAH_ABUSE_SCAN && !path) return 0;
    kept = 0;
    for (i = 0; i < entry->count[event]; ++i) {
        uint64_t then = entry->times[event][i];
        if (now_ns >= then && now_ns - then < windows[event]) {
            entry->times[event][kept] = then;
            if (event == ANKAH_ABUSE_SCAN)
                entry->path_hashes[kept] = entry->path_hashes[i];
            ++kept;
        }
    }
    if (kept == 40) {
        memmove(entry->times[event], entry->times[event] + 1,
                39 * sizeof(entry->times[event][0]));
        if (event == ANKAH_ABUSE_SCAN)
            memmove(entry->path_hashes, entry->path_hashes + 1, 39);
        kept = 39;
    }
    entry->times[event][kept] = now_ns;
    if (event == ANKAH_ABUSE_SCAN) entry->path_hashes[kept] = (unsigned char)hash_path(path);
    entry->count[event] = kept + 1;
    if (event == ANKAH_ABUSE_SCAN) {
        memset(entry->paths, 0, sizeof(entry->paths));
        for (i = 0; i < entry->count[event]; ++i) {
            unsigned int bit = entry->path_hashes[i];
            entry->paths[bit / 64] |= UINT64_C(1) << (bit % 64);
        }
    }
    if (entry->count[event] < limits[event] ||
        (event == ANKAH_ABUSE_SCAN && path_bits(entry->paths) <
         (policy->profile == ANKAH_ABUSE_STRICT ? 16U : 32U)) ||
        (entry->signaled && now_ns >= entry->signal_ns &&
         now_ns - entry->signal_ns < 60 * SECOND)) return 0;
    ++policy->signals[event];
    entry->signaled = 1;
    entry->signal_ns = now_ns;
    return 1;
}
