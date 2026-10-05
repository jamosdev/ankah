#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <uv.h>

/* Gate the mascot worker before encoding, so lifecycle checks do not depend
 * on image complexity or CPU timing. Loaded only by the Linux test fixture. */
static uv_work_cb original_work;
static uv_after_work_cb original_after;

static void mark(const char *name) {
    const char *path = getenv(name);
    int file;
    if (!path) return;
    file = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (file < 0) abort();
    close(file);
}

static void gated_work(uv_work_t *work) {
    const char *release = getenv("ANKAH_MASCOT_RELEASE");
    mark("ANKAH_MASCOT_ENTERED");
    while (access(release, F_OK) != 0) usleep(1000);
    original_work(work);
}

static void gated_after(uv_work_t *work, int status) {
    original_after(work, status);
    mark("ANKAH_MASCOT_FINISHED");
}

int uv_cancel(uv_req_t *request) {
    static int (*original)(uv_req_t *);
    if (!original) original = dlsym(RTLD_NEXT, "uv_cancel");
    if (request->type == UV_WORK) mark("ANKAH_MASCOT_CANCELLED");
    return original(request);
}

int uv_queue_work(uv_loop_t *loop, uv_work_t *work, uv_work_cb callback,
                  uv_after_work_cb after) {
    static int (*original)(uv_loop_t *, uv_work_t *, uv_work_cb, uv_after_work_cb);
    if (!original) original = dlsym(RTLD_NEXT, "uv_queue_work");
    if (getenv("ANKAH_MASCOT_ENTERED") && getenv("ANKAH_MASCOT_RELEASE")) {
        original_work = callback;
        original_after = after;
        return original(loop, work, gated_work, gated_after);
    }
    return original(loop, work, callback, after);
}
