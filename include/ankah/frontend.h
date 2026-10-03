#ifndef ANKAH_FRONTEND_H
#define ANKAH_FRONTEND_H

#include <stddef.h>
#include <stdint.h>
#include <uv.h>
#include "ankah/http.h"
#include "ankah/host.h"

#define ANKAH_FRONTEND_MAX_CONNECTIONS 256

typedef struct {
    uv_loop_t *loop;
    ankah_host *hosts;
    unsigned int host_count, max_connections, max_streams;
    size_t upload_queue, request_queue, response_queue;
    const char *certificate_path;
    const char *key_path;
    const char *internal_key;
    int internal_port;
    int http3_port;
    int (*admit)(const ankah_request *request, const char *host,
                 const char *direct_peer, int *rate_class, int *proved,
                 int *crawler, int *bing_claim);
    void (*drained)(void *data);
    void *drained_data;
} ankah_frontend_options;

void ankah_frontend_response_deadline(unsigned int bridge_port, uint64_t deadline_ns);

int ankah_frontend_init(const ankah_frontend_options *options);
void ankah_frontend_accept(uv_stream_t *server, int status);
void ankah_frontend_begin_drain(void);
void ankah_frontend_force_close(void);
int ankah_frontend_is_drained(void);
void ankah_frontend_shutdown(void);
unsigned int ankah_frontend_connections(void);
uint64_t ankah_frontend_next_crawler_slot_id(void);
void ankah_frontend_release_crawler_slot(uint64_t slot_id);

#endif
