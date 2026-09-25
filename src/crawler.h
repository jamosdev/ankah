#ifndef ANKAH_CRAWLER_H
#define ANKAH_CRAWLER_H

#include <uv.h>

/* Initializes the published common-crawler address ranges. */
int ankah_crawlers_init(void);

typedef void (*ankah_bingbot_callback)(void *data, int verified);

/* Google ranges are authoritative and do not need DNS. */
int ankah_google_crawler_is_known(const char *ip);

/* The crawler pool and Bing verifier each permit exactly one operation. */
int ankah_crawler_acquire(void);
void ankah_crawler_release(void);

/* A cached result is returned immediately. Otherwise start performs one
 * asynchronous reverse lookup followed by a matching forward lookup. */
int ankah_bingbot_cache_lookup(const char *ip, int *verified);
int ankah_bingbot_verify_start(uv_loop_t *loop, const char *ip,
                               ankah_bingbot_callback callback, void *data);
void ankah_bingbot_verify_cancel(void *data);

#endif
