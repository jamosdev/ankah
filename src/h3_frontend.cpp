#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <nghttp3/nghttp3.h>
#include <llhttp.h>

extern "C" {
#include "ankah/h3_frontend.h"
#include "ankah/http.h"
#include "ankah/language.h"
#include "ankah/stats.h"
#include "crawler.h"
}

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr size_t MAX_CONNECTIONS = 256;
constexpr size_t MAX_STREAMS = 32;
constexpr size_t MAX_GLOBAL_STREAMS = 256;
constexpr size_t MAX_UNKNOWN_BODY = 16U * 1024U * 1024U;
constexpr size_t MAX_CONNECTION_BODY = 64U * 1024U * 1024U;
constexpr size_t MAX_GLOBAL_BODY = 64U * 1024U * 1024U;
constexpr size_t MAX_STREAM_REQUEST_QUEUE = 512U * 1024U;
constexpr size_t MAX_GLOBAL_REQUEST_QUEUE = 128U * 1024U * 1024U;
constexpr size_t MAX_STREAM_RESPONSE_QUEUE = 2U * 1024U * 1024U;
constexpr size_t MAX_CONNECTION_RESPONSE_QUEUE = 8U * 1024U * 1024U;
constexpr size_t MAX_GLOBAL_RESPONSE_QUEUE = 64U * 1024U * 1024U;
constexpr size_t MAX_PENDING_UDP_SENDS = 4096;
constexpr size_t CID_LENGTH = 18;
constexpr uint64_t HANDSHAKE_TIMEOUT = 10 * NGTCP2_SECONDS;
constexpr uint64_t IDLE_TIMEOUT = 120 * NGTCP2_SECONDS;

struct Server;
struct Connection;
struct Stream;
void allocation(uv_handle_t *, size_t, uv_buf_t *);
void core_read(uv_stream_t *, ssize_t, const uv_buf_t *);

struct Send {
    uv_udp_send_t request{};
    std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> bytes{};
    Server *server = nullptr;
};

struct CoreWrite {
    uv_write_t request{};
    std::string bytes;
    Stream *stream = nullptr;
    size_t body_bytes = 0;
};

struct ResponseChunk {
    std::string bytes;
    size_t acknowledged = 0;
};

struct Stream {
    Connection *owner = nullptr;
    int64_t id = -1;
    ankah_request request{};
    std::string authority;
    std::string scheme;
    std::string body;
    std::string request_head;
    std::deque<std::string> request_queue;
    std::deque<std::unique_ptr<ResponseChunk>> response_queue;
    std::deque<std::unique_ptr<ResponseChunk>> response_inflight;
    std::vector<ankah_header> response_headers;
    std::vector<ankah_header> response_trailers;
    size_t header_size = 0;
    size_t declared_length = 0;
    size_t received = 0;
    size_t request_queued = 0;
    size_t response_queued = 0;
    size_t body_offset = 0;
    bool has_length = false;
    bool saw_method = false;
    bool saw_path = false;
    bool saw_authority = false;
    bool headers_done = false;
    bool request_done = false;
    bool dispatched = false;
    bool stopped = false;
    bool response_started = false;
    bool response_done = false;
    bool response_has_body = true;
    bool core_open = false;
    bool core_connected = false;
    bool core_paused = false;
    bool writing = false;
    bool head_written = false;
    bool failed = false;
    bool closed = false;
    bool admitted = false;
    bool proved = false;
    bool crawler_slot = false;
    bool bing_claim = false;
    bool drain_tracked = false;
    bool drain_rejected = false;
    uint64_t crawler_slot_id = 0;
    int status = 0;
    int header_stage = 0;
    int response_status = 0;
    uv_tcp_t core{};
    uv_connect_t connect{};
    llhttp_t parser{};
    llhttp_settings_t parser_settings{};

    ~Stream();
    void fail(int code, const char *message);
    void dispatch();
    void write_next();
    void close_core();
    void submit_response();
    void append_response(const char *data, size_t size);
    void finish_response();
};

struct Connection {
    Server *server = nullptr;
    ngtcp2_conn *quic = nullptr;
    nghttp3_conn *http = nullptr;
    SSL *ssl = nullptr;
    ngtcp2_crypto_conn_ref ref{};
    ngtcp2_cid cid{};
    sockaddr_storage peer{};
    sockaddr_storage local{};
    socklen_t peer_len = 0;
    socklen_t local_len = 0;
    std::map<int64_t, std::unique_ptr<Stream>> streams;
    std::vector<std::string> cids;
    std::string peer_ip;
    uint64_t created_at = 0;
    size_t unknown_body = 0;
    size_t response_queued = 0;
    unsigned core_handles = 0;
    bool failed = false;
    bool closing = false;
    bool drained = false;
    bool handshake_done = false;

    ~Connection();
    Stream *find_stream(int64_t id);
    void setup_http();
    void flush();
    void close();
};

struct Server {
    ankah_frontend_options options{};
    uv_udp_t udp{};
    uv_timer_t timer{};
    SSL_CTX *tls = nullptr;
    sockaddr_storage address{};
    socklen_t address_len = 0;
    std::map<std::string, Connection *> by_cid;
    std::vector<std::unique_ptr<Connection>> connections;
    std::array<uint8_t, 32> secret{};
    size_t unknown_body = 0;
    size_t request_queued = 0;
    size_t response_queued = 0;
    size_t stream_count = 0;
    size_t pending_sends = 0;
    uint64_t next_crawler_slot = 0;
    bool udp_open = false;
    bool timer_open = false;
    bool draining = false;
    bool shutting_down = false;
    bool active = false;
    bool drained_notified = false;

    void receive(const sockaddr *peer, const uint8_t *data, size_t length);
    void send(const sockaddr *peer, const uint8_t *data, size_t length);
    void tick();
};

Server *server = nullptr;

std::string cid_key(const uint8_t *data, size_t length) {
    return std::string(reinterpret_cast<const char *>(data), length);
}

socklen_t addr_length(const sockaddr *address) {
    return address->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

bool same_address(const sockaddr_storage &left, const sockaddr *right) {
    if (left.ss_family != right->sa_family) return false;
    if (right->sa_family == AF_INET) {
        auto a = reinterpret_cast<const sockaddr_in *>(&left);
        auto b = reinterpret_cast<const sockaddr_in *>(right);
        return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    auto a = reinterpret_cast<const sockaddr_in6 *>(&left);
    auto b = reinterpret_cast<const sockaddr_in6 *>(right);
    return a->sin6_port == b->sin6_port &&
        a->sin6_scope_id == b->sin6_scope_id &&
        std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0;
}

ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
    return static_cast<Connection *>(ref->user_data)->quic;
}

void random_bytes(uint8_t *dest, size_t length, const ngtcp2_rand_ctx *) {
    if (RAND_bytes(dest, static_cast<int>(length)) != 1) std::abort();
}

int new_cid(ngtcp2_conn *, ngtcp2_cid *cid,
            ngtcp2_stateless_reset_token *token, size_t length, void *data) {
    auto *c = static_cast<Connection *>(data);
    if (RAND_bytes(cid->data, static_cast<int>(length)) != 1) return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = length;
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token->data, c->server->secret.data(), c->server->secret.size(), cid) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    auto key = cid_key(cid->data, cid->datalen);
    c->server->by_cid[key] = c;
    c->cids.push_back(key);
    return 0;
}

int remove_cid(ngtcp2_conn *, const ngtcp2_cid *cid, void *data) {
    auto *c = static_cast<Connection *>(data);
    auto key = cid_key(cid->data, cid->datalen);
    c->server->by_cid.erase(key);
    c->cids.erase(std::remove(c->cids.begin(), c->cids.end(), key), c->cids.end());
    return 0;
}

int alpn_select(SSL *, const uint8_t **out, uint8_t *outlen,
                const uint8_t *in, unsigned int length, void *) {
    for (size_t offset = 0; offset < length;) {
        size_t count = in[offset++];
        if (count > length - offset) break;
        if (count == 2 && std::memcmp(in + offset, "h3", 2) == 0) {
            *out = in + offset;
            *outlen = 2;
            return SSL_TLSEXT_ERR_OK;
        }
        offset += count;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

Connection::~Connection() {
    if (server) {
        for (const auto &key : cids) {
            auto it = server->by_cid.find(key);
            if (it != server->by_cid.end() && it->second == this)
                server->by_cid.erase(it);
        }
    }
    if (http) nghttp3_conn_del(http);
    if (quic) ngtcp2_conn_del(quic);
    if (ssl) SSL_free(ssl);
}

Stream::~Stream() {
    if (crawler_slot) ankah_crawler_release();
    auto *s = owner->server;
    s->unknown_body -= body.size();
    owner->unknown_body -= body.size();
    s->request_queued -= request_queued;
    s->response_queued -= response_queued;
    owner->response_queued -= response_queued;
    --s->stream_count;
}

Stream *Connection::find_stream(int64_t id) {
    auto it = streams.find(id);
    return it == streams.end() ? nullptr : it->second.get();
}

void Connection::close() {
    if (closing) return;
    closing = true;
    for (auto &entry : streams) entry.second->close_core();
}

int receive_header(nghttp3_conn *, int64_t, int32_t,
                   nghttp3_rcbuf *name_buf, nghttp3_rcbuf *value_buf,
                   uint8_t, void *, void *stream_data) {
    auto *stream = static_cast<Stream *>(stream_data);
    if (!stream || stream->failed) return 0;
    auto name = nghttp3_rcbuf_get_buf(name_buf);
    auto value = nghttp3_rcbuf_get_buf(value_buf);
    if (name.len > ANKAH_MAX_FIELD || value.len >= ANKAH_MAX_VALUE ||
        stream->header_size + name.len + value.len > ANKAH_HEADER_LIMIT) {
        stream->failed = true;
        return 0;
    }
    stream->header_size += name.len + value.len;
    std::string key(reinterpret_cast<const char *>(name.base), name.len);
    std::string text(reinterpret_cast<const char *>(value.base), value.len);
    if (std::any_of(text.begin(), text.end(), [](unsigned char ch) {
            return ch < 0x20 || ch == 0x7f;
        })) {
        stream->failed = true;
        return 0;
    }
    if (!key.empty() && key[0] == ':') {
        if (stream->headers_done) { stream->failed = true; return 0; }
        if (key == ":method" && !stream->saw_method && text.size() < sizeof(stream->request.method)) {
            std::memcpy(stream->request.method, text.c_str(), text.size() + 1);
            stream->saw_method = true;
        } else if (key == ":path" && !stream->saw_path &&
                   text.size() < sizeof(stream->request.target)) {
            std::memcpy(stream->request.target, text.c_str(), text.size() + 1);
            stream->saw_path = true;
        } else if (key == ":authority" && !stream->saw_authority &&
                   text.size() < ANKAH_MAX_VALUE) {
            stream->authority = text;
            stream->saw_authority = true;
        } else if (key == ":scheme" && stream->scheme.empty()) {
            stream->scheme = text;
        } else stream->failed = true;
        return 0;
    }
    if (stream->request.count >= ANKAH_MAX_HEADERS || key.empty()) {
        stream->failed = true;
        return 0;
    }
    auto *header = &stream->request.headers[stream->request.count++];
    if (ankah_header_set_name(header, key.data(), key.size()) != 0) {
        stream->failed = true;
        return 0;
    }
    std::memcpy(header->value, text.c_str(), text.size() + 1);
    if (key == "content-length") {
        if (stream->has_length || text.empty()) { stream->failed = true; return 0; }
        size_t parsed = 0;
        for (unsigned char ch : text) {
            if (ch < '0' || ch > '9' || parsed > (SIZE_MAX - (ch - '0')) / 10) {
                stream->failed = true;
                return 0;
            }
            parsed = parsed * 10 + (ch - '0');
        }
        stream->has_length = true;
        stream->declared_length = parsed;
    }
    return 0;
}

int begin_headers(nghttp3_conn *http, int64_t stream_id, void *data, void *) {
    auto *c = static_cast<Connection *>(data);
    auto *stream = c->find_stream(stream_id);
    if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
    return nghttp3_conn_set_stream_user_data(http, stream_id, stream);
}

int end_headers(nghttp3_conn *, int64_t, int, void *, void *data) {
    auto *stream = static_cast<Stream *>(data);
    if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
    stream->headers_done = true;
    if (stream->drain_rejected) {
        stream->fail(503, "Server draining\n");
        return 0;
    }
    if (stream->failed || !stream->saw_method || !stream->saw_path ||
        !stream->saw_authority || stream->scheme != "https" ||
        stream->request.target[0] != '/') {
        stream->fail(400, "Invalid HTTP/3 request\n");
        return 0;
    }
    int rate_class = 0, proved = 0, crawler = 0, bing_claim = 0;
    int status = stream->owner->server->options.admit(
        &stream->request, stream->authority.c_str(), stream->owner->peer_ip.c_str(),
        &rate_class, &proved, &crawler, &bing_claim);
    if (status) {
        stream->fail(status, status == 429 ? "Rate limit exceeded\n" :
                     status == 421 ? "Unexpected Host\n" :
                     "Invalid forwarding information\n");
        return 0;
    }
    if ((crawler || bing_claim) && ankah_crawler_acquire() != 0) {
        stream->fail(429, "Crawler concurrency exceeded\n");
        return 0;
    }
    stream->crawler_slot = crawler || bing_claim;
    stream->bing_claim = bing_claim;
    if (bing_claim) {
        auto *s = stream->owner->server;
        if (++s->next_crawler_slot == 0) ++s->next_crawler_slot;
        stream->crawler_slot_id = s->next_crawler_slot;
    }
    stream->admitted = true;
    stream->proved = proved;
    if (!stream->has_length && stream->request_done) stream->dispatch();
    else if (stream->has_length) stream->dispatch();
    return 0;
}

int begin_trailers(nghttp3_conn *, int64_t, void *, void *data) {
    auto *stream = static_cast<Stream *>(data);
    if (stream) stream->fail(400, "HTTP/3 request trailers are unsupported\n");
    return 0;
}

int receive_data(nghttp3_conn *, int64_t, const uint8_t *data, size_t length,
                 void *, void *stream_data) {
    auto *stream = static_cast<Stream *>(stream_data);
    if (!stream || stream->failed || stream->stopped) return 0;
    auto *c = stream->owner;
    auto *s = c->server;
    if (stream->has_length) {
        if (stream->received > stream->declared_length ||
            length > stream->declared_length - stream->received) {
            stream->fail(400, "Invalid HTTP/3 request body length\n");
            return 0;
        }
        if (length > MAX_STREAM_REQUEST_QUEUE - stream->request_queued ||
            length > MAX_GLOBAL_REQUEST_QUEUE - s->request_queued) {
            stream->fail(503, "Request body queue unavailable\n");
            return 0;
        }
        stream->request_queue.emplace_back(reinterpret_cast<const char *>(data), length);
        stream->request_queued += length;
        s->request_queued += length;
        stream->received += length;
        stream->write_next();
    } else {
        if (length > MAX_UNKNOWN_BODY - stream->body.size()) {
            stream->fail(413, "Request body too large\n");
            return 0;
        }
        if (length > MAX_CONNECTION_BODY - c->unknown_body ||
            length > MAX_GLOBAL_BODY - s->unknown_body) {
            stream->fail(503, "Request body buffer unavailable\n");
            return 0;
        }
        stream->body.append(reinterpret_cast<const char *>(data), length);
        stream->received += length;
        c->unknown_body += length;
        s->unknown_body += length;
        ngtcp2_conn_extend_max_stream_offset(c->quic, stream->id, length);
        ngtcp2_conn_extend_max_offset(c->quic, length);
    }
    return 0;
}

int end_stream(nghttp3_conn *, int64_t, void *, void *data) {
    auto *stream = static_cast<Stream *>(data);
    if (!stream) return 0;
    stream->request_done = true;
    if (stream->has_length && stream->received != stream->declared_length)
        stream->fail(400, "Invalid HTTP/3 request body length\n");
    else if (!stream->has_length && stream->headers_done) stream->dispatch();
    return 0;
}

int http_stop_sending(nghttp3_conn *, int64_t id, uint64_t code,
                      void *data, void *) {
    auto *c = static_cast<Connection *>(data);
    return ngtcp2_conn_shutdown_stream_read(c->quic, 0, id, code) == 0 ?
        0 : NGHTTP3_ERR_CALLBACK_FAILURE;
}

int http_reset_stream(nghttp3_conn *, int64_t id, uint64_t code,
                      void *data, void *) {
    auto *c = static_cast<Connection *>(data);
    return ngtcp2_conn_shutdown_stream_write(c->quic, 0, id, code) == 0 ?
        0 : NGHTTP3_ERR_CALLBACK_FAILURE;
}

int acked_http_data(nghttp3_conn *, int64_t, uint64_t length,
                    void *, void *data) {
    auto *stream = static_cast<Stream *>(data);
    if (!stream) return 0;
    while (length && !stream->response_inflight.empty()) {
        auto &chunk = stream->response_inflight.front();
        size_t remaining = chunk->bytes.size() - chunk->acknowledged;
        size_t count = static_cast<size_t>(std::min<uint64_t>(length, remaining));
        chunk->acknowledged += count;
        length -= count;
        stream->response_queued -= count;
        stream->owner->response_queued -= count;
        stream->owner->server->response_queued -= count;
        if (chunk->acknowledged == chunk->bytes.size())
            stream->response_inflight.pop_front();
    }
    if (stream->core_open && stream->core_paused &&
        stream->response_queued < MAX_STREAM_RESPONSE_QUEUE / 2 &&
        stream->owner->response_queued < MAX_CONNECTION_RESPONSE_QUEUE / 2 &&
        stream->owner->server->response_queued < MAX_GLOBAL_RESPONSE_QUEUE / 2) {
        stream->core_paused = false;
        uv_read_start(reinterpret_cast<uv_stream_t *>(&stream->core), allocation,
                      core_read);
    }
    return 0;
}

nghttp3_ssize read_response(nghttp3_conn *, int64_t, nghttp3_vec *vectors,
                           size_t count, uint32_t *flags, void *, void *data) {
    auto *stream = static_cast<Stream *>(data);
    if (!stream || !count) return NGHTTP3_ERR_CALLBACK_FAILURE;
    if (stream->response_queue.empty()) {
        if (stream->response_done) {
            *flags |= NGHTTP3_DATA_FLAG_EOF;
            if (!stream->response_trailers.empty())
                *flags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
            return 0;
        }
        return NGHTTP3_ERR_WOULDBLOCK;
    }
    auto chunk = std::move(stream->response_queue.front());
    stream->response_queue.pop_front();
    vectors[0].base = reinterpret_cast<uint8_t *>(chunk->bytes.data());
    vectors[0].len = chunk->bytes.size();
    stream->response_inflight.push_back(std::move(chunk));
    return 1;
}

int acked_quic_data(ngtcp2_conn *, int64_t id, uint64_t offset,
                    uint64_t length, void *data, void *) {
    auto *c = static_cast<Connection *>(data);
    (void)offset;
    return c->http ? nghttp3_conn_add_ack_offset(c->http, id, length) : 0;
}

int stream_open(ngtcp2_conn *, int64_t id, void *data) {
    auto *c = static_cast<Connection *>(data);
    if (!ngtcp2_is_bidi_stream(id)) return 0;
    if (c->streams.size() >= MAX_STREAMS ||
        c->server->stream_count >= MAX_GLOBAL_STREAMS)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    auto stream = std::make_unique<Stream>();
    stream->owner = c;
    stream->id = id;
    stream->drain_tracked = true;
    stream->drain_rejected = c->server->draining;
    c->streams.emplace(id, std::move(stream));
    ++c->server->stream_count;
    return 0;
}

int stream_close(ngtcp2_conn *, uint32_t flags, int64_t id,
                 uint64_t rx_error, uint64_t tx_error, void *data, void *) {
    auto *c = static_cast<Connection *>(data);
    if (c->http) {
        uint32_t hflags = 0;
        if (flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET)
            hflags |= NGHTTP3_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET;
        if (flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET)
            hflags |= NGHTTP3_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET;
        nghttp3_conn_close_stream2(c->http, id, hflags, rx_error, tx_error);
    }
    if (auto *stream = c->find_stream(id)) {
        stream->closed = true;
        stream->close_core();
    }
    return 0;
}

int stream_reset(ngtcp2_conn *, int64_t id, uint64_t, uint64_t,
                 void *data, void *) {
    auto *c = static_cast<Connection *>(data);
    if (auto *stream = c->find_stream(id)) {
        stream->stopped = true;
        stream->close_core();
    }
    return 0;
}

int receive_stop_sending(ngtcp2_conn *, int64_t id, uint64_t,
                         void *data, void *) {
    auto *c = static_cast<Connection *>(data);
    if (auto *stream = c->find_stream(id)) {
        stream->stopped = true;
        stream->close_core();
    }
    return 0;
}

int receive_quic_data(ngtcp2_conn *, uint32_t flags, int64_t id,
                      uint64_t, const uint8_t *data, size_t length,
                      void *user_data, void *) {
    auto *c = static_cast<Connection *>(user_data);
    if (!c->http) return 0;
    auto consumed = nghttp3_conn_read_stream2(c->http, id, data, length,
        flags & NGTCP2_STREAM_DATA_FLAG_FIN, uv_hrtime());
    if (consumed < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
    ngtcp2_conn_extend_max_stream_offset(c->quic, id, static_cast<uint64_t>(consumed));
    ngtcp2_conn_extend_max_offset(c->quic, static_cast<uint64_t>(consumed));
    return 0;
}

int handshake_completed(ngtcp2_conn *, void *data) {
    static_cast<Connection *>(data)->handshake_done = true;
    return 0;
}

int receive_tx_key(ngtcp2_conn *, ngtcp2_encryption_level level, void *data) {
    if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT)
        static_cast<Connection *>(data)->setup_http();
    return static_cast<Connection *>(data)->failed ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

void Connection::setup_http() {
    if (http || closing) return;
    nghttp3_callbacks callbacks{};
    callbacks.acked_stream_data = acked_http_data;
    callbacks.recv_data = receive_data;
    callbacks.begin_headers = begin_headers;
    callbacks.recv_header = receive_header;
    callbacks.end_headers = end_headers;
    callbacks.begin_trailers = begin_trailers;
    callbacks.end_stream = end_stream;
    callbacks.stop_sending = http_stop_sending;
    callbacks.reset_stream = http_reset_stream;
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.max_field_section_size = ANKAH_HEADER_LIMIT;
    settings.qpack_max_dtable_capacity = 0;
    settings.qpack_blocked_streams = 0;
    if (nghttp3_conn_server_new(&http, &callbacks, &settings, nghttp3_mem_default(), this) != 0) {
        failed = true;
        return;
    }
    nghttp3_conn_set_max_client_streams_bidi(http, MAX_STREAMS);
    nghttp3_conn_set_max_concurrent_streams(http, MAX_STREAMS + 8);
    int64_t control, encoder, decoder;
    if (ngtcp2_conn_open_uni_stream(quic, &control, nullptr) != 0 ||
        ngtcp2_conn_open_uni_stream(quic, &encoder, nullptr) != 0 ||
        ngtcp2_conn_open_uni_stream(quic, &decoder, nullptr) != 0 ||
        nghttp3_conn_bind_control_stream(http, control) != 0 ||
        nghttp3_conn_bind_qpack_streams(http, encoder, decoder) != 0)
        failed = true;
}

bool hop_header(const std::string &name) {
    return name == "connection" || name == "keep-alive" ||
        name == "proxy-connection" || name == "transfer-encoding" ||
        name == "upgrade" || name == "te";
}

std::string lowercase(std::string text) {
    for (char &ch : text) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return text;
}

void Stream::close_core() {
    if (core_open && !uv_is_closing(reinterpret_cast<uv_handle_t *>(&core)))
        uv_close(reinterpret_cast<uv_handle_t *>(&core), [](uv_handle_t *handle) {
            auto *stream = static_cast<Stream *>(handle->data);
            stream->core_open = false;
            --stream->owner->core_handles;
        });
}

void Stream::fail(int code, const char *message) {
    if (owner->quic)
        ngtcp2_conn_shutdown_stream_read(owner->quic, 0, id,
                                         NGHTTP3_H3_REQUEST_CANCELLED);
    failed = true;
    stopped = true;
    if (response_started) {
        if (owner->quic) ngtcp2_conn_shutdown_stream_write(
            owner->quic, 0, id, NGHTTP3_H3_INTERNAL_ERROR);
        close_core();
        return;
    }
    close_core();
    std::string body_text = message;
    response_status = code;
    response_headers.clear();
    response_trailers.clear();
    auto add = [this](const char *name, const std::string &value) {
        ankah_header header{};
        ankah_header_set_name(&header, name, std::strlen(name));
        std::snprintf(header.value, sizeof(header.value), "%s", value.c_str());
        response_headers.push_back(header);
    };
    add("content-type", "text/plain; charset=utf-8");
    add("content-length", std::to_string(body_text.size()));
    add("cache-control", "no-store");
    if (code == 429 || code == 503) add("retry-after", "1");
    submit_response();
    append_response(body_text.data(), body_text.size());
    response_done = true;
    if (owner->http) nghttp3_conn_resume_stream(owner->http, id);
    owner->flush();
}

void Stream::submit_response() {
    if (!owner->http || response_started) return;
    std::string code = std::to_string(response_status);
    std::vector<nghttp3_nv> headers;
    std::vector<std::string> names;
    std::vector<std::string> values;
    headers.reserve(response_headers.size() + 1);
    names.reserve(response_headers.size() + 1);
    values.reserve(response_headers.size() + 1);
    auto add = [&headers, &names, &values](
                   const std::string &name, const std::string &value) {
        names.push_back(name);
        values.push_back(value);
        nghttp3_nv header{};
        header.name = reinterpret_cast<uint8_t *>(names.back().data());
        header.namelen = names.back().size();
        header.value = reinterpret_cast<uint8_t *>(values.back().data());
        header.valuelen = values.back().size();
        headers.push_back(header);
    };
    add(":status", code);
    for (const auto &header : response_headers) {
        std::string name = lowercase(header.name);
        if (hop_header(name)) continue;
        add(name, header.value);
    }
    response_has_body = std::strcmp(request.method, "HEAD") != 0 &&
        response_status != 204 && response_status != 304;
    nghttp3_data_reader reader{};
    reader.read_data = read_response;
    int result = nghttp3_conn_submit_response(owner->http, id, headers.data(),
        headers.size(), response_has_body ? &reader : nullptr);
    if (result != 0) owner->failed = true;
    else response_started = true;
}

void Stream::append_response(const char *data, size_t size) {
    if (!size || !response_has_body) return;
    auto *s = owner->server;
    if (size > MAX_STREAM_RESPONSE_QUEUE - response_queued ||
        size > MAX_CONNECTION_RESPONSE_QUEUE - owner->response_queued ||
        size > MAX_GLOBAL_RESPONSE_QUEUE - s->response_queued) {
        owner->failed = true;
        return;
    }
    auto chunk = std::make_unique<ResponseChunk>();
    chunk->bytes.assign(data, size);
    response_queue.push_back(std::move(chunk));
    response_queued += size;
    owner->response_queued += size;
    s->response_queued += size;
    if (owner->http) nghttp3_conn_resume_stream(owner->http, id);
}

void Stream::finish_response() {
    response_done = true;
    if (response_started && !response_trailers.empty()) {
        std::vector<nghttp3_nv> headers;
        std::vector<std::string> names;
        headers.reserve(response_trailers.size());
        names.reserve(response_trailers.size());
        for (const auto &header : response_trailers) {
            std::string name = lowercase(header.name);
            if (hop_header(name)) continue;
            names.push_back(name);
            nghttp3_nv value{};
            value.name = reinterpret_cast<uint8_t *>(names.back().data());
            value.namelen = names.back().size();
            value.value = reinterpret_cast<uint8_t *>(const_cast<char *>(header.value));
            value.valuelen = std::strlen(header.value);
            headers.push_back(value);
        }
        if (!headers.empty() &&
            nghttp3_conn_submit_trailers(owner->http, id, headers.data(), headers.size()) != 0)
            owner->failed = true;
    }
    if (owner->http) nghttp3_conn_resume_stream(owner->http, id);
    owner->flush();
}

int response_begin(llhttp_t *parser) {
    auto *stream = static_cast<Stream *>(parser->data);
    if (stream->response_done) return HPE_USER;
    stream->response_headers.clear();
    stream->response_trailers.clear();
    stream->header_stage = 0;
    return 0;
}

int response_field(llhttp_t *parser, const char *at, size_t length) {
    auto *stream = static_cast<Stream *>(parser->data);
    auto &headers = stream->response_started ?
        stream->response_trailers : stream->response_headers;
    if (stream->header_stage != 1) {
        if (headers.size() >= ANKAH_MAX_HEADERS) return HPE_USER;
        headers.emplace_back();
        stream->header_stage = 1;
    }
    auto &field = headers.back();
    size_t used = std::strlen(field.name);
    if (length >= sizeof(field.name) - used) return HPE_USER;
    std::memcpy(field.name + used, at, length);
    field.name[used + length] = 0;
    return 0;
}

int response_value(llhttp_t *parser, const char *at, size_t length) {
    auto *stream = static_cast<Stream *>(parser->data);
    auto &headers = stream->response_started ?
        stream->response_trailers : stream->response_headers;
    if (headers.empty()) return HPE_USER;
    auto &field = headers.back();
    size_t used = std::strlen(field.value);
    if (length >= sizeof(field.value) - used) return HPE_USER;
    std::memcpy(field.value + used, at, length);
    field.value[used + length] = 0;
    stream->header_stage = 2;
    return 0;
}

int response_headers_complete(llhttp_t *parser) {
    auto *stream = static_cast<Stream *>(parser->data);
    stream->response_status = llhttp_get_status_code(parser);
    stream->header_stage = 0;
    if (stream->response_status >= 200) {
        stream->stopped = true;
        stream->submit_response();
    }
    return 0;
}

int response_body(llhttp_t *parser, const char *at, size_t length) {
    auto *stream = static_cast<Stream *>(parser->data);
    if (stream->response_started) stream->append_response(at, length);
    return stream->owner->failed ? HPE_USER : 0;
}

int response_complete(llhttp_t *parser) {
    auto *stream = static_cast<Stream *>(parser->data);
    if (stream->response_started) stream->finish_response();
    return 0;
}

void core_read(uv_stream_t *handle, ssize_t count, const uv_buf_t *buffer) {
    auto *stream = static_cast<Stream *>(handle->data);
    if (count > 0 && !stream->owner->closing) {
        if (llhttp_execute(&stream->parser, buffer->base, static_cast<size_t>(count)) != HPE_OK) {
            stream->fail(502, "Invalid upstream response\n");
        } else {
            if (stream->response_queued >= MAX_STREAM_RESPONSE_QUEUE - 16384 ||
                stream->owner->response_queued >= MAX_CONNECTION_RESPONSE_QUEUE - 16384 ||
                stream->owner->server->response_queued >= MAX_GLOBAL_RESPONSE_QUEUE - 16384) {
                uv_read_stop(handle);
                stream->core_paused = true;
            }
            stream->owner->flush();
        }
    } else if (count < 0) {
        if (llhttp_finish(&stream->parser) != HPE_OK || !stream->response_started)
            stream->fail(502, "Incomplete upstream response\n");
        else if (!stream->response_done) stream->finish_response();
        stream->close_core();
    }
    std::free(buffer->base);
}

void core_written(uv_write_t *request, int status) {
    std::unique_ptr<CoreWrite> item(static_cast<CoreWrite *>(request->data));
    auto *stream = item->stream;
    stream->writing = false;
    if (item->body_bytes && stream->has_length) {
        stream->request_queued -= item->body_bytes;
        stream->owner->server->request_queued -= item->body_bytes;
        ngtcp2_conn_extend_max_stream_offset(stream->owner->quic, stream->id,
                                               item->body_bytes);
        ngtcp2_conn_extend_max_offset(stream->owner->quic, item->body_bytes);
    }
    if (status < 0) stream->fail(502, "Upstream write failed\n");
    else stream->write_next();
    stream->owner->flush();
}

void Stream::write_next() {
    if (writing || !core_connected || stopped || owner->closing) return;
    auto item = std::make_unique<CoreWrite>();
    item->stream = this;
    if (!head_written) {
        item->bytes = request_head;
        head_written = true;
    } else if (has_length) {
        if (request_queue.empty()) return;
        item->bytes = std::move(request_queue.front());
        request_queue.pop_front();
        item->body_bytes = item->bytes.size();
    } else {
        if (body_offset >= body.size()) return;
        size_t count = std::min<size_t>(16384, body.size() - body_offset);
        item->bytes.assign(body.data() + body_offset, count);
        body_offset += count;
    }
    item->request.data = item.get();
    uv_buf_t buffer = uv_buf_init(item->bytes.data(),
                                  static_cast<unsigned int>(item->bytes.size()));
    writing = true;
    if (uv_write(&item->request, reinterpret_cast<uv_stream_t *>(&core),
                 &buffer, 1, core_written) != 0) {
        writing = false;
        fail(502, "Upstream write failed\n");
    } else item.release();
}

void on_core_connected(uv_connect_t *request, int status) {
    auto *stream = static_cast<Stream *>(request->data);
    if (status < 0 || stream->owner->closing) {
        stream->fail(502, "Upstream unavailable\n");
        return;
    }
    stream->core_connected = true;
    stream->request_head = std::string(stream->request.method) + " " +
        stream->request.target + " HTTP/1.1\r\nHost: " + stream->authority + "\r\n";
    for (unsigned i = 0; i < stream->request.count; ++i) {
        const auto &field = stream->request.headers[i];
        std::string name = lowercase(field.name);
        if (hop_header(name) || name == "host" || name == "content-length" ||
            name == "expect" || name.rfind("x-ankah-internal-", 0) == 0) continue;
        stream->request_head += name + ": " + field.value + "\r\n";
    }
    auto *s = stream->owner->server;
    stream->request_head += "Content-Length: " +
        std::to_string(stream->has_length ? stream->declared_length : stream->body.size()) +
        "\r\nX-Ankah-Internal-Key: " + s->options.internal_key +
        "\r\nX-Ankah-Internal-Peer: " + stream->owner->peer_ip +
        "\r\nX-Ankah-Internal-Language-Logged: 1\r\n";
    if (stream->bing_claim)
        stream->request_head += "X-Ankah-Internal-Crawler-Slot: " +
            std::to_string(stream->crawler_slot_id) + "\r\n";
    else stream->request_head += std::string("X-Ankah-Internal-Rate-Checked: 1\r\n") +
        "X-Ankah-Internal-Proved: " + (stream->proved ? "1\r\n" : "0\r\n");
    if (stream->drain_tracked) stream->request_head += "X-Ankah-Internal-Drain: 1\r\n";
    stream->request_head += "\r\n";
    if (stream->request_head.size() > ANKAH_HEADER_LIMIT + 512) {
        stream->fail(431, "Request headers too large\n");
        return;
    }
    llhttp_settings_init(&stream->parser_settings);
    stream->parser_settings.on_message_begin = response_begin;
    stream->parser_settings.on_header_field = response_field;
    stream->parser_settings.on_header_value = response_value;
    stream->parser_settings.on_headers_complete = response_headers_complete;
    stream->parser_settings.on_body = response_body;
    stream->parser_settings.on_message_complete = response_complete;
    llhttp_init(&stream->parser, HTTP_RESPONSE, &stream->parser_settings);
    stream->parser.data = stream;
    if (uv_read_start(reinterpret_cast<uv_stream_t *>(&stream->core),
                      allocation, core_read) != 0) {
        stream->fail(502, "Upstream unavailable\n");
        return;
    }
    stream->write_next();
}

void Stream::dispatch() {
    if (dispatched || failed || owner->closing) return;
    dispatched = true;
    ankah_language_log_request(&request);
    sockaddr_in address{};
    if (uv_ip4_addr("127.0.0.1", owner->server->options.internal_port, &address) != 0 ||
        uv_tcp_init(owner->server->options.loop, &core) != 0) {
        fail(503, "Unavailable\n");
        return;
    }
    core_open = true;
    ++owner->core_handles;
    core.data = this;
    connect.data = this;
    if (uv_tcp_connect(&connect, &core,
                       reinterpret_cast<const sockaddr *>(&address), on_core_connected) != 0)
        fail(502, "Upstream unavailable\n");
}

void on_send(uv_udp_send_t *request, int) {
    auto *item = static_cast<Send *>(request->data);
    --item->server->pending_sends;
    delete item;
}

void Server::send(const sockaddr *peer, const uint8_t *data, size_t length) {
    if (!udp_open || length > NGTCP2_MAX_UDP_PAYLOAD_SIZE ||
        pending_sends >= MAX_PENDING_UDP_SENDS) return;
    auto *item = new (std::nothrow) Send;
    if (!item) return;
    item->server = this;
    std::memcpy(item->bytes.data(), data, length);
    item->request.data = item;
    uv_buf_t buffer = uv_buf_init(reinterpret_cast<char *>(item->bytes.data()),
                                  static_cast<unsigned int>(length));
    if (uv_udp_send(&item->request, &udp, &buffer, 1, peer, on_send) != 0)
        delete item;
    else ++pending_sends;
}

void Connection::flush() {
    if (closing || !quic) return;
    std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> packet{};
    for (unsigned count = 0; count < 128; ++count) {
        ngtcp2_path_storage storage;
        ngtcp2_path_storage_zero(&storage);
        ngtcp2_pkt_info info{};
        ngtcp2_ssize written = 0;
        ngtcp2_ssize consumed = -1;
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_vec vectors[16]{};
        nghttp3_ssize vector_count = 0;
        if (http && ngtcp2_conn_get_max_data_left2(quic)) {
            vector_count = nghttp3_conn_writev_stream(http, &stream_id, &fin, vectors, 16);
            if (vector_count < 0) { failed = true; return; }
        }
        uint32_t flags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
        written = ngtcp2_conn_writev_stream(
            quic, &storage.path, &info, packet.data(), packet.size(), &consumed,
            flags, stream_id, reinterpret_cast<const ngtcp2_vec *>(vectors),
            static_cast<size_t>(vector_count), uv_hrtime());
        if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            if (http) nghttp3_conn_block_stream(http, stream_id);
            continue;
        }
        if (written == NGTCP2_ERR_STREAM_SHUT_WR) {
            if (http) nghttp3_conn_shutdown_stream_write(http, stream_id);
            continue;
        }
        if (written < 0) { failed = true; return; }
        if (consumed >= 0 && http &&
            nghttp3_conn_add_write_offset(http, stream_id, static_cast<uint64_t>(consumed)) != 0) {
            failed = true;
            return;
        }
        if (written == 0) break;
        server->send(storage.path.remote.addr, packet.data(), static_cast<size_t>(written));
    }
}

void Server::tick() {
    uint64_t now = uv_hrtime();
    for (auto &entry : connections) {
        Connection *c = entry.get();
        if (c->failed || c->closing) { c->close(); continue; }
        if (!c->handshake_done && now - c->created_at > HANDSHAKE_TIMEOUT) {
            c->close();
            continue;
        }
        if (ngtcp2_conn_get_expiry2(c->quic) <= now &&
            ngtcp2_conn_handle_expiry(c->quic, now) != 0) {
            c->close();
            continue;
        }
        c->flush();
        if (ngtcp2_conn_in_draining_period2(c->quic)) c->close();
        for (auto it = c->streams.begin(); it != c->streams.end();) {
            if (it->second->closed && !it->second->core_open &&
                !it->second->writing) it = c->streams.erase(it);
            else ++it;
        }
    }
    connections.erase(std::remove_if(connections.begin(), connections.end(),
        [this](const std::unique_ptr<Connection> &item) {
            if (!item->closing || item->core_handles) return false;
            for (const auto &key : item->cids) by_cid.erase(key);
            return true;
        }), connections.end());
    if (draining && !drained_notified) {
        bool work = false;
        for (const auto &entry : connections)
            if (entry->core_handles || !entry->streams.empty()) {
                work = true;
                break;
            }
        if (!work) {
            drained_notified = true;
            if (options.drained) options.drained(options.drained_data);
        }
    }
}

void allocation(uv_handle_t *, size_t suggested, uv_buf_t *buffer) {
    size_t length = std::min<size_t>(suggested, 16384);
    buffer->base = static_cast<char *>(std::malloc(length));
    buffer->len = buffer->base ? length : 0;
}

void receive_udp(uv_udp_t *handle, ssize_t count, const uv_buf_t *buffer,
                 const sockaddr *address, unsigned) {
    auto *s = static_cast<Server *>(handle->data);
    if (count > 0 && address)
        s->receive(address, reinterpret_cast<const uint8_t *>(buffer->base),
                   static_cast<size_t>(count));
    std::free(buffer->base);
}

void timer_tick(uv_timer_t *handle) {
    static_cast<Server *>(handle->data)->tick();
}

void close_server_handle(uv_handle_t *) {}

void Server::receive(const sockaddr *peer, const uint8_t *data, size_t length) {
    ngtcp2_version_cid decoded{};
    int result = ngtcp2_pkt_decode_version_cid(&decoded, data, length, CID_LENGTH);
    if (result == NGTCP2_ERR_VERSION_NEGOTIATION) {
        uint32_t version = NGTCP2_PROTO_VER_V1;
        std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> packet{};
        auto written = ngtcp2_pkt_write_version_negotiation(
            packet.data(), std::min(packet.size(), length * 3), 0,
            decoded.scid, decoded.scidlen, decoded.dcid, decoded.dcidlen,
            &version, 1);
        if (written > 0) send(peer, packet.data(), static_cast<size_t>(written));
        return;
    }
    if (result != 0) return;
    auto key = cid_key(decoded.dcid, decoded.dcidlen);
    Connection *c = nullptr;
    auto it = by_cid.find(key);
    if (it != by_cid.end()) c = it->second;
    if (!c) {
        if (draining || connections.size() >= MAX_CONNECTIONS ||
            length < NGTCP2_MAX_UDP_PAYLOAD_SIZE) return;
        ngtcp2_pkt_hd header{};
        if (ngtcp2_accept(&header, data, length) != 0 ||
            header.type != NGTCP2_PKT_INITIAL) return;
        if (!header.tokenlen) {
            ngtcp2_cid retry_cid{};
            retry_cid.datalen = CID_LENGTH;
            if (RAND_bytes(retry_cid.data, CID_LENGTH) != 1) return;
            std::array<uint8_t, NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2> token{};
            auto token_size = ngtcp2_crypto_generate_retry_token2(
                token.data(), secret.data(), secret.size(), header.version,
                peer, addr_length(peer), &retry_cid, &header.dcid,
                static_cast<uint64_t>(std::time(nullptr)) * NGTCP2_SECONDS);
            if (token_size < 0) return;
            std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> packet{};
            auto written = ngtcp2_crypto_write_retry(
                packet.data(), std::min(packet.size(), length * 3),
                header.version, &header.scid, &retry_cid, &header.dcid,
                token.data(), static_cast<size_t>(token_size));
            if (written > 0) send(peer, packet.data(), static_cast<size_t>(written));
            return;
        }
        ngtcp2_cid original_cid{};
        if (ngtcp2_crypto_verify_retry_token2(
                &original_cid, header.token, header.tokenlen,
                secret.data(), secret.size(), header.version,
                peer, addr_length(peer), &header.dcid,
                10 * NGTCP2_SECONDS,
                static_cast<uint64_t>(std::time(nullptr)) * NGTCP2_SECONDS) != 0)
            return;
        auto item = std::make_unique<Connection>();
        c = item.get();
        c->server = this;
        c->created_at = uv_hrtime();
        c->peer_len = addr_length(peer);
        c->local_len = address_len;
        std::memcpy(&c->peer, peer, c->peer_len);
        std::memcpy(&c->local, &address, address_len);
        char ip[INET6_ADDRSTRLEN]{};
        if (peer->sa_family == AF_INET6)
            uv_ip6_name(reinterpret_cast<const sockaddr_in6 *>(peer), ip, sizeof(ip));
        else uv_ip4_name(reinterpret_cast<const sockaddr_in *>(peer), ip, sizeof(ip));
        c->peer_ip = ip;
        c->cid = header.dcid;
        c->ref.get_conn = get_conn;
        c->ref.user_data = c;
        ngtcp2_callbacks callbacks{};
        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.handshake_completed = handshake_completed;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = receive_quic_data;
        callbacks.acked_stream_data_offset = acked_quic_data;
        callbacks.stream_open = stream_open;
        callbacks.stream_close2 = stream_close;
        callbacks.stream_reset = stream_reset;
        callbacks.recv_stop_sending = receive_stop_sending;
        callbacks.rand = random_bytes;
        callbacks.remove_connection_id = remove_cid;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        callbacks.recv_tx_key = receive_tx_key;
        callbacks.get_new_connection_id2 = new_cid;
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
        ngtcp2_settings settings{};
        ngtcp2_settings_default(&settings);
        settings.initial_ts = c->created_at;
        settings.token = header.token;
        settings.tokenlen = header.tokenlen;
        settings.token_type = NGTCP2_TOKEN_TYPE_RETRY;
        ngtcp2_transport_params params{};
        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_remote = MAX_STREAM_REQUEST_QUEUE;
        params.initial_max_stream_data_bidi_local = 64U * 1024U;
        params.initial_max_stream_data_uni = 64U * 1024U;
        params.initial_max_data = 16U * 1024U * 1024U;
        params.initial_max_streams_bidi = MAX_STREAMS;
        params.initial_max_streams_uni = 8;
        params.max_idle_timeout = IDLE_TIMEOUT;
        params.original_dcid = original_cid;
        params.original_dcid_present = 1;
        params.retry_scid = header.dcid;
        params.retry_scid_present = 1;
        params.active_connection_id_limit = 4;
        ngtcp2_path path{};
        ngtcp2_addr_init(&path.local, reinterpret_cast<sockaddr *>(&c->local),
                         c->local_len);
        ngtcp2_addr_init(&path.remote, reinterpret_cast<sockaddr *>(&c->peer),
                         c->peer_len);
        if (ngtcp2_conn_server_new(&c->quic, &header.scid, &header.dcid,
                                   &path, header.version, &callbacks, &settings,
                                   &params, nullptr, c) != 0) return;
        c->ssl = SSL_new(tls);
        if (!c->ssl) return;
        SSL_set_app_data(c->ssl, &c->ref);
        SSL_set_accept_state(c->ssl);
        ngtcp2_conn_set_tls_native_handle(c->quic, c->ssl);
        c->cids.push_back(key);
        by_cid[key] = c;
        connections.push_back(std::move(item));
    }
    if (c->closing || !same_address(c->peer, peer)) return;
    ngtcp2_path path{};
    ngtcp2_addr_init(&path.local, reinterpret_cast<sockaddr *>(&c->local),
                     c->local_len);
    ngtcp2_addr_init(&path.remote, reinterpret_cast<sockaddr *>(&c->peer),
                     c->peer_len);
    ngtcp2_pkt_info info{};
    result = ngtcp2_conn_read_pkt(c->quic, &path, &info, data, length, uv_hrtime());
    if (result != 0) {
        if (result == NGTCP2_ERR_RETRY && c->quic) return;
        c->failed = true;
        return;
    }
    c->flush();
}

} // namespace

extern "C" int ankah_h3_init(const ankah_frontend_options *options,
                              const sockaddr *address) {
    if (server || !options || !address) return -1;
    auto *item = new (std::nothrow) Server;
    if (!item) return -1;
    item->options = *options;
    item->address_len = addr_length(address);
    std::memcpy(&item->address, address, item->address_len);
    if (RAND_bytes(item->secret.data(), item->secret.size()) != 1) goto failed;
    item->tls = SSL_CTX_new(TLS_server_method());
    if (!item->tls ||
        ngtcp2_crypto_boringssl_configure_server_context(item->tls) != 0 ||
        SSL_CTX_use_certificate_chain_file(item->tls, options->certificate_path) != 1 ||
        SSL_CTX_use_PrivateKey_file(item->tls, options->key_path, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(item->tls) != 1) goto failed;
    SSL_CTX_set_alpn_select_cb(item->tls, alpn_select, nullptr);
    SSL_CTX_set_options(item->tls, SSL_OP_NO_TICKET);
    if (uv_udp_init(options->loop, &item->udp) != 0) goto failed;
    item->udp_open = true;
    item->udp.data = item;
    if (uv_udp_bind(&item->udp, address, 0) != 0 ||
        uv_udp_recv_start(&item->udp, allocation, receive_udp) != 0)
        goto failed;
    if (uv_timer_init(options->loop, &item->timer) != 0) goto failed;
    item->timer_open = true;
    item->timer.data = item;
    if (uv_timer_start(&item->timer, timer_tick, 25, 25) != 0) goto failed;
    item->active = true;
    server = item;
    return 0;
failed:
    if (item->timer_open) uv_close(reinterpret_cast<uv_handle_t *>(&item->timer),
                                   close_server_handle);
    if (item->udp_open) uv_close(reinterpret_cast<uv_handle_t *>(&item->udp),
                                 close_server_handle);
    if (item->tls) SSL_CTX_free(item->tls);
    return -1;
}

extern "C" void ankah_h3_begin_drain(void) {
    if (!server) return;
    server->draining = true;
    for (auto &entry : server->connections) {
        if (entry->http) nghttp3_conn_submit_shutdown_notice(entry->http);
        entry->flush();
    }
}

extern "C" void ankah_h3_force_close(void) {
    if (!server) return;
    server->draining = true;
    for (auto &entry : server->connections) entry->close();
    if (server->timer_open &&
        !uv_is_closing(reinterpret_cast<uv_handle_t *>(&server->timer))) {
        uv_timer_stop(&server->timer);
        uv_close(reinterpret_cast<uv_handle_t *>(&server->timer), close_server_handle);
    }
    if (server->udp_open &&
        !uv_is_closing(reinterpret_cast<uv_handle_t *>(&server->udp))) {
        uv_udp_recv_stop(&server->udp);
        uv_close(reinterpret_cast<uv_handle_t *>(&server->udp), close_server_handle);
    }
    server->active = false;
}

extern "C" int ankah_h3_is_drained(void) {
    if (!server) return 1;
    for (const auto &entry : server->connections)
        if (entry->core_handles || !entry->streams.empty()) return 0;
    return 1;
}

extern "C" void ankah_h3_shutdown(void) {
    if (!server) return;
    ankah_h3_force_close();
    if (server->tls) SSL_CTX_free(server->tls);
    server->tls = nullptr;
    if (!uv_loop_alive(server->options.loop)) {
        delete server;
        server = nullptr;
    }
}

extern "C" int ankah_h3_active(void) {
    return server && server->active && !server->draining;
}

extern "C" int ankah_h3_release_crawler_slot(uint64_t slot_id) {
    if (!server || !slot_id) return 0;
    for (auto &connection : server->connections) {
        for (auto &entry : connection->streams) {
            auto *stream = entry.second.get();
            if (stream->crawler_slot && stream->crawler_slot_id == slot_id) {
                stream->crawler_slot = false;
                ankah_crawler_release();
                return 1;
            }
        }
    }
    return 0;
}

extern "C" int ankah_h3_reload_credentials(void) {
    if (!server || !server->active) return 0;
    SSL_CTX *replacement = SSL_CTX_new(TLS_server_method());
    if (!replacement) return -1;
    if (ngtcp2_crypto_boringssl_configure_server_context(replacement) != 0 ||
        SSL_CTX_use_certificate_chain_file(
            replacement, server->options.certificate_path) != 1 ||
        SSL_CTX_use_PrivateKey_file(
            replacement, server->options.key_path, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(replacement) != 1) {
        SSL_CTX_free(replacement);
        return -1;
    }
    SSL_CTX_set_alpn_select_cb(replacement, alpn_select, nullptr);
    SSL_CTX_set_options(replacement, SSL_OP_NO_TICKET);
    SSL_CTX *previous = server->tls;
    server->tls = replacement;
    SSL_CTX_free(previous);
    return 0;
}
