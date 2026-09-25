#ifndef ANKAH_DOTS_POLICY_H
#define ANKAH_DOTS_POLICY_H
/* Pure helpers for the optional RFC 8783 DOTS data channel client. */
#include <stddef.h>
#include <stdint.h>

#define ANKAH_DOTS_MAX_THRESHOLD 64
#define ANKAH_DOTS_TRACKED 1024
#define ANKAH_DOTS_NAME_MAX 80

typedef struct {
    char ip[64];
    uint64_t seen_ns;
    uint64_t times[ANKAH_DOTS_MAX_THRESHOLD];
    unsigned int count;
} ankah_dots_tracked;

typedef struct {
    ankah_dots_tracked entries[ANKAH_DOTS_TRACKED];
} ankah_dots_tracker;

/* Records one challenged request. Returns 1 when ip has now made threshold
 * requests within window_ns; the ip's history is then cleared. The table
 * is bounded and evicts the least recently seen address. */
int ankah_dots_tracker_hit(ankah_dots_tracker *tracker, const char *ip,
                           uint64_t now_ns, unsigned int threshold, uint64_t window_ns);

/* "ankah-" followed by the address with '.' and ':' replaced by '-'. */
int ankah_dots_acl_name(const char *ip, char *out, size_t capacity);

/* RFC 8783 ietf-dots-data-channel:acls body with one ACE that drops TCP from
 * ip/32 (or /128) to destination on port. destination is a CIDR of the same
 * address family as ip. Returns the length or -1. */
int ankah_dots_acl_body(const char *name, const char *ip, const char *destination,
                        unsigned int port, char *out, size_t capacity);

/* RFC 8783 dots-client registration body. */
int ankah_dots_client_body(const char *cuid, char *out, size_t capacity);

/* True for a cuid that is safe in a URL path segment and a JSON string. */
int ankah_dots_valid_cuid(const char *cuid);

/* Status code of an HTTP/1.x response head, or -1. */
int ankah_dots_status(const char *response, size_t size);

/* Collects the values of JSON "name" members that start with prefix.
 * Returns how many were stored. */
size_t ankah_dots_scan_names(const char *body, size_t size, const char *prefix,
                             char names[][ANKAH_DOTS_NAME_MAX], size_t max);
#endif
