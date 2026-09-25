#ifndef ANKAH_DOTS_H
#define ANKAH_DOTS_H
/* Optional RFC 8783 DOTS data channel client. Disabled unless dots-server
 * is configured. When enabled, repeated challenged requests from one
 * trusted-proxy-resolved client install a source and destination scoped
 * filtering ACL at the DOTS server, which Ankah withdraws after a fixed
 * time. DOTS failures never change how requests are handled. */
#include <stdint.h>
#include <uv.h>

typedef struct {
    uint64_t escalations;
    uint64_t dropped;
    uint64_t ok[4];
    uint64_t failed[4];
    unsigned int active;
    int registered;
} ankah_dots_counters;

enum { ANKAH_DOTS_OP_REGISTER, ANKAH_DOTS_OP_LIST, ANKAH_DOTS_OP_INSTALL,
       ANKAH_DOTS_OP_WITHDRAW, ANKAH_DOTS_OPS };

/* name excludes the "dots-" prefix. Returns 0, or -1 for an invalid value. */
int ankah_dots_option(const char *name, const char *value);
/* True for options whose value is a file path. */
int ankah_dots_path_option(const char *name);
/* Validates the collected options. trusted_proxies is the number of
 * configured trusted proxy networks, which DOTS requires. */
int ankah_dots_finish(unsigned int trusted_proxies);
int ankah_dots_enabled(void);
int ankah_dots_start(uv_loop_t *loop);
/* ip is the resolved client address. Call only for trusted direct peers. */
void ankah_dots_record(const char *ip, uint64_t now_ns);
void ankah_dots_close(void);
void ankah_dots_counters_get(ankah_dots_counters *out);
const char *ankah_dots_operation_name(int operation);
#endif
