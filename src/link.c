#include "link.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINK_CIPHER_LIMIT (256U * 1024U)
#define LINK_PLAIN_LIMIT (4U * 1024U * 1024U)
#define LINK_QUEUE_LIMIT (4U * 1024U * 1024U)
#define LINK_CONNECTION_LIMIT 40

typedef struct link_frame link_frame;
struct link_frame {
    link_frame *next;
    size_t size, offset;
    unsigned char data[];
};

typedef struct {
    uv_write_t request;
    uv_buf_t buffer;
    struct ankah_link_connection *connection;
} link_write;

typedef struct {
    ankah_link_peer address;
    uv_timer_t retry;
    uv_getaddrinfo_t lookup;
    struct sockaddr_storage resolved[16];
    unsigned int resolved_count, next_address;
    struct ankah_link_connection *connection;
    int resolving, retry_initialized;
} link_peer_state;

struct ankah_link_connection {
    uv_tcp_t tcp;
    uv_connect_t connect;
    mbedtls_ssl_context ssl;
    struct ankah_link_connection *previous, *next;
    link_peer_state *peer;
    unsigned char *cipher, *plain;
    size_t cipher_size, cipher_offset, plain_size;
    link_frame *first, *last;
    size_t queued_plain;
    unsigned int pending_writes, references;
    int outgoing, connected, handshake, closing, driving, drive_again;
};

typedef struct {
    uv_loop_t *loop;
    uv_tcp_t listener;
    int listener_initialized, running, stopping;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_ssl_config client_tls, server_tls;
    link_peer_state peers[ANKAH_LINK_MAX_PEERS];
    size_t peer_count;
    ankah_link_connection *first;
    unsigned int connections;
    uint64_t bytes_sent;
    ankah_link_callback callback;
    void *owner;
} link_state;

static link_state link;

static void drive(ankah_link_connection *connection);
static void close_connection(ankah_link_connection *connection);
static void retry_peer(link_peer_state *peer);
static void connect_next(link_peer_state *peer);

static void release_connection(ankah_link_connection *connection) {
    link_frame *frame;
    if (--connection->references) return;
    if (connection->previous) connection->previous->next = connection->next;
    else link.first = connection->next;
    if (connection->next) connection->next->previous = connection->previous;
    frame = connection->first;
    while (frame) {
        link_frame *next = frame->next;
        free(frame);
        frame = next;
    }
    free(connection->cipher);
    free(connection->plain);
    mbedtls_ssl_free(&connection->ssl);
    --link.connections;
    free(connection);
}

static void on_tcp_closed(uv_handle_t *handle) {
    release_connection(handle->data);
}

static void close_connection(ankah_link_connection *connection) {
    if (connection->closing) return;
    connection->closing = 1;
    uv_read_stop((uv_stream_t *)&connection->tcp);
    if (connection->peer && connection->peer->connection == connection) {
        connection->peer->connection = NULL;
        if (connection->handshake)
            connection->peer->next_address = connection->peer->resolved_count;
        if (!link.stopping) retry_peer(connection->peer);
    }
    uv_close((uv_handle_t *)&connection->tcp, on_tcp_closed);
}

static int tls_receive(void *context, unsigned char *out, size_t capacity) {
    ankah_link_connection *connection = context;
    size_t available = connection->cipher_size - connection->cipher_offset;
    if (!available) return MBEDTLS_ERR_SSL_WANT_READ;
    if (capacity > available) capacity = available;
    memcpy(out, connection->cipher + connection->cipher_offset, capacity);
    connection->cipher_offset += capacity;
    if (connection->cipher_offset == connection->cipher_size) {
        free(connection->cipher);
        connection->cipher = NULL;
        connection->cipher_size = connection->cipher_offset = 0;
    }
    return (int)capacity;
}

static void on_cipher_write(uv_write_t *request, int status) {
    link_write *write = request->data;
    ankah_link_connection *connection = write->connection;
    free(write->buffer.base);
    free(write);
    --connection->pending_writes;
    if (status < 0) close_connection(connection);
    else if (!connection->closing) drive(connection);
    release_connection(connection);
}

static int tls_send(void *context, const unsigned char *data, size_t size) {
    ankah_link_connection *connection = context;
    link_write *write;
    uv_buf_t buffer;
    if (connection->closing) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if (connection->pending_writes >= 16) return MBEDTLS_ERR_SSL_WANT_WRITE;
    write = calloc(1, sizeof(*write));
    if (!write) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    write->buffer.base = malloc(size ? size : 1);
    if (!write->buffer.base) { free(write); return MBEDTLS_ERR_SSL_ALLOC_FAILED; }
    memcpy(write->buffer.base, data, size);
    write->buffer.len = (unsigned int)size;
    write->connection = connection;
    write->request.data = write;
    buffer = write->buffer;
    ++connection->references;
    ++connection->pending_writes;
    if (uv_write(&write->request, (uv_stream_t *)&connection->tcp,
                 &buffer, 1, on_cipher_write) != 0) {
        --connection->pending_writes;
        --connection->references;
        free(write->buffer.base);
        free(write);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    link.bytes_sent += size;
    return (int)size;
}

static int append_cipher(ankah_link_connection *connection,
                         const unsigned char *data, size_t size) {
    size_t available = connection->cipher_size - connection->cipher_offset;
    unsigned char *grown;
    if (size > LINK_CIPHER_LIMIT - available) return -1;
    grown = malloc(available + size);
    if (!grown) return -1;
    if (available)
        memcpy(grown, connection->cipher + connection->cipher_offset, available);
    memcpy(grown + available, data, size);
    free(connection->cipher);
    connection->cipher = grown;
    connection->cipher_offset = 0;
    connection->cipher_size = available + size;
    return 0;
}

static uint32_t get_u32(const unsigned char *data) {
    return (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 |
           (uint32_t)data[2] << 8 | (uint32_t)data[3];
}

static void put_u32(unsigned char *data, uint32_t value) {
    data[0] = (unsigned char)(value >> 24);
    data[1] = (unsigned char)(value >> 16);
    data[2] = (unsigned char)(value >> 8);
    data[3] = (unsigned char)value;
}

static int append_plain(ankah_link_connection *connection,
                        const unsigned char *data, size_t size) {
    unsigned char *grown;
    size_t used = 0;
    if (size > LINK_PLAIN_LIMIT - connection->plain_size) return -1;
    grown = realloc(connection->plain, connection->plain_size + size);
    if (!grown) return -1;
    connection->plain = grown;
    memcpy(connection->plain + connection->plain_size, data, size);
    connection->plain_size += size;
    while (connection->plain_size - used >= 4) {
        size_t length = get_u32(connection->plain + used);
        if (!length || length > ANKAH_LINK_MESSAGE_MAX) return -1;
        if (connection->plain_size - used < length + 4) break;
        link.callback(connection->plain[used + 4],
                      connection->plain + used + 5, length - 1,
                      connection, link.owner);
        if (connection->closing) return -1;
        used += length + 4;
    }
    if (used) {
        connection->plain_size -= used;
        if (connection->plain_size)
            memmove(connection->plain, connection->plain + used, connection->plain_size);
    }
    return 0;
}

static void drive(ankah_link_connection *connection) {
    unsigned char plain[16384];
    int result;
    if (connection->closing) return;
    if (connection->driving) { connection->drive_again = 1; return; }
    connection->driving = 1;
    do {
        connection->drive_again = 0;
        if (!connection->handshake) {
            result = mbedtls_ssl_handshake(&connection->ssl);
            if (result == 0) {
                connection->handshake = 1;
                link.callback(ANKAH_LINK_CONNECTED, NULL, 0, connection, link.owner);
            } else if (result != MBEDTLS_ERR_SSL_WANT_READ &&
                       result != MBEDTLS_ERR_SSL_WANT_WRITE) {
                close_connection(connection);
                break;
            }
        }
        if (!connection->handshake || connection->closing) continue;
        while (connection->first && !connection->closing) {
            link_frame *frame = connection->first;
            size_t piece = frame->size - frame->offset;
            if (piece > 16384) piece = 16384;
            result = mbedtls_ssl_write(&connection->ssl,
                                       frame->data + frame->offset, piece);
            if (result > 0) {
                frame->offset += (size_t)result;
                connection->queued_plain -= (size_t)result;
                if (frame->offset == frame->size) {
                    connection->first = frame->next;
                    if (!connection->first) connection->last = NULL;
                    free(frame);
                }
            } else if (result == MBEDTLS_ERR_SSL_WANT_READ ||
                       result == MBEDTLS_ERR_SSL_WANT_WRITE) break;
            else { close_connection(connection); break; }
        }
        while (!connection->closing) {
            result = mbedtls_ssl_read(&connection->ssl, plain, sizeof(plain));
            if (result > 0) {
                if (append_plain(connection, plain, (size_t)result) != 0)
                    close_connection(connection);
            } else if (result == MBEDTLS_ERR_SSL_WANT_READ ||
                       result == MBEDTLS_ERR_SSL_WANT_WRITE) break;
            else { close_connection(connection); break; }
        }
    } while (connection->drive_again && !connection->closing);
    connection->driving = 0;
}

static void allocate_read(uv_handle_t *handle, size_t suggested, uv_buf_t *buffer) {
    (void)handle; (void)suggested;
    buffer->base = malloc(16384);
    buffer->len = buffer->base ? 16384 : 0;
}

static void on_read(uv_stream_t *stream, ssize_t count, const uv_buf_t *buffer) {
    ankah_link_connection *connection = stream->data;
    if (count > 0 && !connection->closing) {
        if (append_cipher(connection, (const unsigned char *)buffer->base,
                          (size_t)count) != 0) close_connection(connection);
        else drive(connection);
    } else if (count < 0) close_connection(connection);
    free(buffer->base);
}

static ankah_link_connection *new_connection(link_peer_state *peer, int outgoing) {
    ankah_link_connection *connection;
    if (link.connections >= LINK_CONNECTION_LIMIT) return NULL;
    connection = calloc(1, sizeof(*connection));
    if (!connection) return NULL;
    mbedtls_ssl_init(&connection->ssl);
    if (uv_tcp_init(link.loop, &connection->tcp) != 0) {
        mbedtls_ssl_free(&connection->ssl);
        free(connection);
        return NULL;
    }
    connection->tcp.data = connection;
    connection->references = 1;
    connection->peer = peer;
    connection->outgoing = outgoing;
    connection->next = link.first;
    if (link.first) link.first->previous = connection;
    link.first = connection;
    ++link.connections;
    if (peer) peer->connection = connection;
    return connection;
}

static int setup_tls(ankah_link_connection *connection) {
    mbedtls_ssl_config *config = connection->outgoing ?
        &link.client_tls : &link.server_tls;
    if (mbedtls_ssl_setup(&connection->ssl, config) != 0) return -1;
    mbedtls_ssl_set_bio(&connection->ssl, connection, tls_send, tls_receive, NULL);
    (void)uv_tcp_keepalive(&connection->tcp, 1, 30);
    if (uv_read_start((uv_stream_t *)&connection->tcp, allocate_read, on_read) != 0)
        return -1;
    drive(connection);
    return 0;
}

static void on_connected(uv_connect_t *request, int status) {
    ankah_link_connection *connection = request->data;
    if (status < 0 || link.stopping || setup_tls(connection) != 0)
        close_connection(connection);
    release_connection(connection);
}

static void on_resolved(uv_getaddrinfo_t *request, int status,
                        struct addrinfo *addresses) {
    link_peer_state *peer = request->data;
    struct addrinfo *at;
    peer->resolving = 0;
    peer->resolved_count = peer->next_address = 0;
    if (!link.stopping && status == 0) {
        for (at = addresses; at; at = at->ai_next) {
            if ((at->ai_family != AF_INET && at->ai_family != AF_INET6) ||
                at->ai_addrlen > sizeof(struct sockaddr_storage) ||
                peer->resolved_count == 16) continue;
            memcpy(&peer->resolved[peer->resolved_count++],
                   at->ai_addr, at->ai_addrlen);
        }
    }
    if (addresses) uv_freeaddrinfo(addresses);
    if (!link.stopping) {
        if (peer->resolved_count) connect_next(peer);
        else retry_peer(peer);
    }
}

static void connect_next(link_peer_state *peer) {
    while (!link.stopping && !peer->connection &&
           peer->next_address < peer->resolved_count) {
        ankah_link_connection *connection = new_connection(peer, 1);
        struct sockaddr_storage *address;
        if (!connection) break;
        address = &peer->resolved[peer->next_address++];
        connection->connect.data = connection;
        ++connection->references;
        if (uv_tcp_connect(&connection->connect, &connection->tcp,
                           (const struct sockaddr *)address, on_connected) == 0)
            return;
        --connection->references;
        close_connection(connection);
    }
    if (!link.stopping && !peer->connection) retry_peer(peer);
}

static void on_retry(uv_timer_t *timer) {
    link_peer_state *peer = timer->data;
    struct addrinfo hints;
    char port[8];
    if (link.stopping || peer->connection || peer->resolving) return;
    if (peer->next_address < peer->resolved_count) {
        connect_next(peer);
        return;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port, sizeof(port), "%d", peer->address.port);
    peer->lookup.data = peer;
    peer->resolving = 1;
    if (uv_getaddrinfo(link.loop, &peer->lookup, on_resolved,
                       peer->address.host, port, &hints) != 0) {
        peer->resolving = 0;
        retry_peer(peer);
    }
}

static void retry_peer(link_peer_state *peer) {
    if (peer->retry_initialized && !link.stopping)
        uv_timer_start(&peer->retry, on_retry, 1000, 0);
}

static void on_incoming(uv_stream_t *server, int status) {
    ankah_link_connection *connection;
    if (status < 0 || link.stopping) return;
    connection = new_connection(NULL, 0);
    if (!connection) return;
    if (uv_accept(server, (uv_stream_t *)&connection->tcp) != 0 ||
        setup_tls(connection) != 0) close_connection(connection);
}

static int setup_config(mbedtls_ssl_config *config, int endpoint,
                        const unsigned char psk[32]) {
    static const int suites[] = {MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384, 0};
    static const unsigned char identity[] = "ankah-link-v1";
    if (mbedtls_ssl_config_defaults(config, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) return -1;
    mbedtls_ssl_conf_rng(config, mbedtls_ctr_drbg_random, &link.random);
    mbedtls_ssl_conf_min_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(config, suites);
    return mbedtls_ssl_conf_psk(config, psk, 32,
                               identity, sizeof(identity) - 1);
}

int ankah_link_start(uv_loop_t *loop,
                     const unsigned char secret[ANKAH_SECRET_SIZE],
                     const char *public_host, const char *listen_ip, int listen_port,
                     const ankah_link_peer *peers, size_t peer_count,
                     ankah_link_callback callback, void *owner) {
    static const unsigned char personalization[] = "ankah link";
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char psk[32];
    char derivation[320];
    struct sockaddr_storage address;
    size_t i;
    int n;
    if (!loop || !secret || !public_host || !listen_ip || !callback ||
        !peer_count || peer_count > ANKAH_LINK_MAX_PEERS || !info ||
        listen_port < 1 || listen_port > 65535) return -1;
    memset(&link, 0, sizeof(link));
    link.loop = loop;
    link.callback = callback;
    link.owner = owner;
    n = snprintf(derivation, sizeof(derivation), "ankah-link-v1|%s", public_host);
    if (n < 0 || (size_t)n >= sizeof(derivation) ||
        mbedtls_md_hmac(info, secret, ANKAH_SECRET_SIZE,
                        (const unsigned char *)derivation, (size_t)n, psk) != 0)
        return -1;
    mbedtls_entropy_init(&link.entropy);
    mbedtls_ctr_drbg_init(&link.random);
    mbedtls_ssl_config_init(&link.client_tls);
    mbedtls_ssl_config_init(&link.server_tls);
    if (mbedtls_ctr_drbg_seed(&link.random, mbedtls_entropy_func, &link.entropy,
                              personalization, sizeof(personalization) - 1) != 0 ||
        setup_config(&link.client_tls, MBEDTLS_SSL_IS_CLIENT, psk) != 0 ||
        setup_config(&link.server_tls, MBEDTLS_SSL_IS_SERVER, psk) != 0)
        return -1;
    memset(psk, 0, sizeof(psk));
    memset(&address, 0, sizeof(address));
    if ((strchr(listen_ip, ':') ?
         uv_ip6_addr(listen_ip, listen_port, (struct sockaddr_in6 *)&address) :
         uv_ip4_addr(listen_ip, listen_port, (struct sockaddr_in *)&address)) != 0 ||
        uv_tcp_init(loop, &link.listener) != 0) return -1;
    link.listener_initialized = 1;
    if (uv_tcp_bind(&link.listener, (const struct sockaddr *)&address, 0) != 0 ||
        uv_listen((uv_stream_t *)&link.listener, 64, on_incoming) != 0) return -1;
    link.peer_count = peer_count;
    for (i = 0; i < peer_count; ++i) {
        link_peer_state *peer = &link.peers[i];
        peer->address = peers[i];
        if (uv_timer_init(loop, &peer->retry) != 0) return -1;
        peer->retry_initialized = 1;
        peer->retry.data = peer;
        uv_timer_start(&peer->retry, on_retry, 0, 0);
    }
    link.running = 1;
    return 0;
}

int ankah_link_send(ankah_link_connection *connection, int type,
                    const void *data, size_t size) {
    link_frame *frame;
    if (!connection || connection->closing || !connection->handshake ||
        type <= 0 || type > 255 || size > ANKAH_LINK_MESSAGE_MAX - 1 ||
        connection->queued_plain > LINK_QUEUE_LIMIT - 5 ||
        size > LINK_QUEUE_LIMIT - connection->queued_plain - 5) return -1;
    frame = malloc(sizeof(*frame) + size + 5);
    if (!frame) return -1;
    frame->next = NULL;
    frame->size = size + 5;
    frame->offset = 0;
    put_u32(frame->data, (uint32_t)(size + 1));
    frame->data[4] = (unsigned char)type;
    if (size) memcpy(frame->data + 5, data, size);
    if (connection->last) connection->last->next = frame;
    else connection->first = frame;
    connection->last = frame;
    connection->queued_plain += frame->size;
    drive(connection);
    return 0;
}

int ankah_link_broadcast(int type, const void *data, size_t size) {
    size_t i;
    int sent = 0;
    for (i = 0; i < link.peer_count; ++i) {
        ankah_link_connection *connection = link.peers[i].connection;
        if (connection && connection->handshake &&
            ankah_link_send(connection, type, data, size) == 0) ++sent;
    }
    return sent;
}

int ankah_link_retain(ankah_link_connection *connection) {
    if (!connection || connection->closing) return -1;
    ++connection->references;
    return 0;
}

void ankah_link_release(ankah_link_connection *connection) {
    if (connection) release_connection(connection);
}

int ankah_link_is_open(const ankah_link_connection *connection) {
    return connection && connection->handshake && !connection->closing;
}

void ankah_link_stop(void) {
    ankah_link_connection *connection = link.first;
    size_t i;
    if (!link.running || link.stopping) return;
    link.stopping = 1;
    if (link.listener_initialized)
        uv_close((uv_handle_t *)&link.listener, NULL);
    for (i = 0; i < link.peer_count; ++i) {
        if (link.peers[i].retry_initialized)
            uv_close((uv_handle_t *)&link.peers[i].retry, NULL);
        if (link.peers[i].resolving)
            (void)uv_cancel((uv_req_t *)&link.peers[i].lookup);
    }
    while (connection) {
        ankah_link_connection *next = connection->next;
        close_connection(connection);
        connection = next;
    }
}

void ankah_link_cleanup(void) {
    mbedtls_ssl_config_free(&link.client_tls);
    mbedtls_ssl_config_free(&link.server_tls);
    mbedtls_ctr_drbg_free(&link.random);
    mbedtls_entropy_free(&link.entropy);
}

uint64_t ankah_link_bytes_sent(void) { return link.bytes_sent; }
