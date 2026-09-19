#ifndef ANKAH_FRONTEND_H
#define ANKAH_FRONTEND_H

#include <stddef.h>
#include <uv.h>

typedef struct {
    uv_loop_t *loop;
    const char *certificate_path;
    const char *key_path;
    const char *internal_key;
    int internal_port;
} ankah_frontend_options;

int ankah_frontend_init(const ankah_frontend_options *options);
void ankah_frontend_accept(uv_stream_t *server, int status);
void ankah_frontend_shutdown(void);

#endif
