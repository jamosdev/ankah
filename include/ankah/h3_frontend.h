#ifndef ANKAH_H3_FRONTEND_H
#define ANKAH_H3_FRONTEND_H

#include "ankah/frontend.h"

#ifdef __cplusplus
extern "C" {
#endif

int ankah_h3_init(const ankah_frontend_options *options,
                  const struct sockaddr *address);
void ankah_h3_begin_drain(void);
void ankah_h3_force_close(void);
int ankah_h3_is_drained(void);
void ankah_h3_shutdown(void);
int ankah_h3_active(void);
int ankah_h3_release_crawler_slot(uint64_t slot_id);
int ankah_h3_reload_credentials(void);

#ifdef __cplusplus
}
#endif

#endif
