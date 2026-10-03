#ifndef ANKAH_LINK_H
#define ANKAH_LINK_H

#include <stddef.h>
#include <stdint.h>
#include <uv.h>
#include "ankah/pow.h"

#define ANKAH_LINK_MAX_PEERS 16
#define ANKAH_LINK_MESSAGE_MAX (3U * 1024U * 1024U)
#define ANKAH_LINK_BLOCK_BATCH_MAX 32

enum {
    ANKAH_LINK_CONNECTED = 0,
    ANKAH_LINK_SOLVED = 1,
    ANKAH_LINK_META = 2,
    ANKAH_LINK_BLOCKS = 3,
    ANKAH_LINK_CONSUME_REQUEST = 4,
    ANKAH_LINK_CONSUME_OK = 5,
    ANKAH_LINK_CONSUME_FAIL = 6
};

typedef struct ankah_link_connection ankah_link_connection;
typedef struct {
    char host[256];
    int port;
} ankah_link_peer;
typedef void (*ankah_link_callback)(int type, const unsigned char *data,
                                    size_t size, ankah_link_connection *connection,
                                    void *owner);

int ankah_link_start(uv_loop_t *loop,
                     const unsigned char secret[ANKAH_SECRET_SIZE],
                     const char *public_host, const char *listen_ip, int listen_port,
                     const ankah_link_peer *peers, size_t peer_count,
                     ankah_link_callback callback, void *owner);
int ankah_link_send(ankah_link_connection *connection, int type,
                    const void *data, size_t size);
int ankah_link_broadcast(int type, const void *data, size_t size);
int ankah_link_retain(ankah_link_connection *connection);
void ankah_link_release(ankah_link_connection *connection);
int ankah_link_is_open(const ankah_link_connection *connection);
void ankah_link_stop(void);
void ankah_link_cleanup(void);
uint64_t ankah_link_bytes_sent(void);

#endif
