#ifndef ANKAH_FRONTEND_H
#define ANKAH_FRONTEND_H

#include <stddef.h>
#include <stdint.h>
#include <uv.h>
#include "ankah/http.h"

#define ANKAH_FRONTEND_MAX_CONNECTIONS 256

typedef struct {
    uv_loop_t *loop;
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

int ankah_frontend_init(const ankah_frontend_options *options);
void ankah_frontend_accept(uv_stream_t *server, int status);
void ankah_frontend_begin_drain(void);
void ankah_frontend_force_close(void);
int ankah_frontend_is_drained(void);
void ankah_frontend_shutdown(void);
unsigned int ankah_frontend_connections(void);
void ankah_frontend_release_crawler_slot(uint64_t slot_id);

#endif
