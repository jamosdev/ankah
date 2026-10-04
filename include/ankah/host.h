#ifndef ANKAH_HOST_H
#define ANKAH_HOST_H
#include "ankah/http.h"
#include "ankah/static.h"
#include <limits.h>
#include <stdint.h>
#define ANKAH_MAX_HOSTS 16
#define ANKAH_MAX_ROUTES 16
#define ANKAH_LOCAL_ROUTE UINT_MAX
typedef struct {
    char id[64], method[16], path[ANKAH_MAX_TARGET];
} ankah_exact_route;
typedef struct {
    char origin[256], authority[256], name[256];
    unsigned int port;
    char certificate[512], key[512], upstream[512];
    char static_directory[512], dashboard_route[ANKAH_MAX_TARGET];
    ankah_static_bundle bundle;
    int primary, static_challenge, static_challenge_seen;
    ankah_exact_route routes[ANKAH_MAX_ROUTES];
    unsigned int route_count, concurrency, active;
    size_t body_limit;
    uint64_t connect_ms, upload_ms, response_ms;
} ankah_host;
int ankah_host_local_path(const ankah_host *host, const char *target);
/* Only case and an omitted configured default port are normalized. */
int ankah_authority(const char *text, unsigned int default_port,
                    char name[256], unsigned int *port);
int ankah_host_origin(ankah_host *host, const char *origin);
int ankah_host_find(const ankah_host *hosts, unsigned int count, const char *authority);
int ankah_host_request(const ankah_host *host, const ankah_request *request,
                       const char *authority, int h2, unsigned int *route);
/* Zero means an absolute deadline has expired; zero inputs are inactive. */
uint64_t ankah_absolute_timeout_ms(uint64_t now, uint64_t first,
                                  uint64_t second, uint64_t third);
/* Shared queued byte budgets for the TLS bridge and core. Event-loop only. */
void ankah_queue_limits(size_t request_limit, size_t response_limit);
int ankah_queue_reserve(int response, size_t bytes);
void ankah_queue_release(int response, size_t bytes);
size_t ankah_queue_current(int response);
size_t ankah_queue_peak(int response);
#endif
