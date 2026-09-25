#ifndef ANKAH_H2_FLOW_POLICY_H
#define ANKAH_H2_FLOW_POLICY_H

#include <stddef.h>

#define ANKAH_H2_STREAM_WINDOW (512U * 1024U)
#define ANKAH_H2_MAX_STREAMS 32U
#define ANKAH_H2_CONNECTION_WINDOW (ANKAH_H2_MAX_STREAMS * ANKAH_H2_STREAM_WINDOW)
/* Each dispatched stream holds one core connection. This backstop is
 * MAX_CONNECTIONS (256) times the 512 KiB stream window. Revisit it if either
 * limit changes. */
#define ANKAH_H2_REQUEST_QUEUE_TOTAL (128U * 1024U * 1024U)

/* Stopped streams discard data uncounted, so END_STREAM cannot show a length error. */
static inline int ankah_h2_end_stream_length_error(int has_content_length,
                                                    int request_stopped,
                                                    size_t received,
                                                    size_t declared) {
    return has_content_length && !request_stopped && received != declared;
}

static inline int ankah_h2_queue_has_room(size_t stream_queued,
                                           size_t total_queued, size_t incoming) {
    return stream_queued <= ANKAH_H2_STREAM_WINDOW &&
           incoming <= ANKAH_H2_STREAM_WINDOW - stream_queued &&
           total_queued <= ANKAH_H2_REQUEST_QUEUE_TOTAL &&
           incoming <= ANKAH_H2_REQUEST_QUEUE_TOTAL - total_queued;
}

static inline int ankah_h2_queue_reserve(size_t *total_queued,
                                          size_t stream_queued, size_t incoming) {
    if (!ankah_h2_queue_has_room(stream_queued, *total_queued, incoming)) return 0;
    *total_queued += incoming;
    return 1;
}

static inline void ankah_h2_queue_release(size_t *total_queued, size_t released) {
    *total_queued -= released <= *total_queued ? released : *total_queued;
}

#endif
