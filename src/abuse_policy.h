#ifndef ANKAH_ABUSE_POLICY_H
#define ANKAH_ABUSE_POLICY_H
#include <stdint.h>

typedef enum { ANKAH_ABUSE_OFF, ANKAH_ABUSE_CONSERVATIVE, ANKAH_ABUSE_STRICT } ankah_abuse_profile;
typedef enum { ANKAH_ABUSE_INVALID_PROOF, ANKAH_ABUSE_CLIENT_RATE,
               ANKAH_ABUSE_SCAN, ANKAH_ABUSE_BODY_STALL, ANKAH_ABUSE_REASONS } ankah_abuse_event;
typedef struct ankah_abuse_policy ankah_abuse_policy;
ankah_abuse_policy *ankah_abuse_create(void);
void ankah_abuse_destroy(ankah_abuse_policy *policy);
void ankah_abuse_set_profile(ankah_abuse_policy *policy, ankah_abuse_profile profile);
uint64_t ankah_abuse_signal_count(const ankah_abuse_policy *policy, ankah_abuse_event event);
/* Returns one when this event reaches a threshold outside the IP cooldown. */
int ankah_abuse_record(ankah_abuse_policy *policy, const char *ip,
                       ankah_abuse_event event, const char *path, uint64_t now_ns);
#endif
