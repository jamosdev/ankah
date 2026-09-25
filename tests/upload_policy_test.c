#include "h2_flow_policy.h"
#include "timeout_policy.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

int main(void) {
    const uint64_t finished = UINT64_C(1000000000000);
    const uint64_t reply = finished + ANKAH_UPLOAD_REPLY_NS;
    size_t queued = ANKAH_H2_REQUEST_QUEUE_TOTAL - ANKAH_H2_STREAM_WINDOW;
    int reserved;

    assert(ankah_reply_deadline_ns(finished, 1, 0, 0) == 0);
    assert(ankah_reply_deadline_ns(finished, 0, 1, 0) == 0);
    assert(ankah_reply_deadline_ns(finished, 1, 1, 0) == reply);
    assert(ankah_reply_deadline_ns(finished, 1, 1, 1) == 0);
    assert(ankah_core_timeout_ms(finished + UINT64_C(1000000000), 0,
                                  reply, 0) == 299000);
    assert(ankah_core_timeout_ms(reply - 1, 0, reply, 0) == 1);
    assert(ankah_core_timeout_ms(reply, 0, reply, 0) == 0);
    assert(ankah_core_timeout_ms(finished, 0, 0, 0) == 30000);
    assert(ankah_core_timeout_ms(finished, 0, 0, 1) == 300000);

    assert(ankah_front_timeout_ms(0, 1, 1, 0, 0) == 10000);
    assert(ankah_front_timeout_ms(1, 1, 1, 0, 0) == 0);
    assert(ankah_front_timeout_ms(1, 1, 0, 0, 0) == 120000);
    assert(ankah_front_timeout_ms(1, 0, 0, 1, 0) == 300000);

    assert(ankah_h2_end_stream_length_error(1, 0, 100, 200));
    assert(!ankah_h2_end_stream_length_error(1, 1, 100, 200));
    assert(!ankah_h2_end_stream_length_error(1, 0, 200, 200));
    assert(!ankah_h2_end_stream_length_error(0, 0, 100, 200));

    assert(ankah_h2_queue_has_room(0, 0, ANKAH_H2_STREAM_WINDOW));
    assert(!ankah_h2_queue_has_room(1, 0, ANKAH_H2_STREAM_WINDOW));
    assert(ankah_h2_queue_has_room(0, ANKAH_H2_REQUEST_QUEUE_TOTAL - 1, 1));
    assert(!ankah_h2_queue_has_room(0, ANKAH_H2_REQUEST_QUEUE_TOTAL, 1));
    reserved = ankah_h2_queue_reserve(&queued, 0, ANKAH_H2_STREAM_WINDOW);
    assert(reserved);
    assert(queued == ANKAH_H2_REQUEST_QUEUE_TOTAL);
    reserved = ankah_h2_queue_reserve(&queued, 0, 1);
    assert(!reserved);
    assert(queued == ANKAH_H2_REQUEST_QUEUE_TOTAL);
    ankah_h2_queue_release(&queued, ANKAH_H2_STREAM_WINDOW);
    reserved = ankah_h2_queue_reserve(&queued, 0, ANKAH_H2_STREAM_WINDOW);
    assert(reserved);
    queued = 10;
    ankah_h2_queue_release(&queued, 20);
    assert(queued == 0);
    return 0;
}
