#ifndef ANKAH_TIMEOUT_POLICY_H
#define ANKAH_TIMEOUT_POLICY_H

#include <stdint.h>

#define ANKAH_UPLOAD_REPLY_NS UINT64_C(300000000000)

static inline uint64_t ankah_reply_deadline_ns(uint64_t now, int large_body,
                                                int body_complete, int final_started) {
    return large_body && body_complete && !final_started ?
           now + ANKAH_UPLOAD_REPLY_NS : 0;
}

/* Zero means the fixed deadline has expired. */
static inline uint64_t ankah_core_timeout_ms(uint64_t now,
                                              uint64_t request_deadline_ns,
                                              uint64_t reply_deadline_ns,
                                              int websocket) {
    uint64_t timeout = websocket || reply_deadline_ns ? 300000 : 30000;
    uint64_t deadline = request_deadline_ns;
    if (reply_deadline_ns && (!deadline || reply_deadline_ns < deadline))
        deadline = reply_deadline_ns;
    if (deadline) {
        uint64_t remaining;
        if (now >= deadline) return 0;
        remaining = (deadline - now + 999999) / 1000000;
        if (remaining < timeout) timeout = remaining;
    }
    return timeout ? timeout : 1;
}

/* Zero leaves the core in charge of an active large HTTP/2 stream. */
static inline uint64_t ankah_front_timeout_ms(int handshake_complete,
                                               int protocol_h2,
                                               unsigned int long_streams,
                                               int bridge_connected,
                                               int close_notify_started) {
    if (!handshake_complete) return 10000;
    if (protocol_h2) return long_streams ? 0 : 120000;
    return bridge_connected && !close_notify_started ? 300000 : 30000;
}

#endif
