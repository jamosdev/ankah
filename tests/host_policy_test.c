#include "ankah/host.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <string.h>
int main(void) {
    ankah_host host = {0};
    ankah_request request = {0};
    unsigned int route = 0, port;
    char name[256];
    const char *bad[] = {"", ":443", "a:", "a:0", "a:65536", "a:0443", "a.",
                         "a..b", "-a", "a-", "a@b", "a/b", "a?", "a#", "a b", "a\\b"};
    size_t i;
    assert(ankah_host_origin(&host, "https://Submit.Example:443") == 0);
    assert(!strcmp(host.name, "submit.example"));
    assert(ankah_host_find(&host, 1, "SUBMIT.EXAMPLE") == 0);
    assert(ankah_host_find(&host, 1, "submit.example:444") == -421);
    for (i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        assert(ankah_authority(bad[i], 443, name, &port) < 0);
    host.route_count = 1; host.defaults.body_limit = 25165824;
    strcpy(host.routes[0].method, "POST"); strcpy(host.routes[0].path, "/v1/smtp");
    strcpy(request.method, "POST"); strcpy(request.target, "/v1/smtp");
    request.count = 1; strcpy(request.headers[0].name, "Host");
    strcpy(request.headers[0].value, "submit.example");
    request.content_length = host.defaults.body_limit;
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 0);
    ++request.content_length;
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 413);
    strcpy(request.method, "GET");
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 405);
    strcpy(request.target, "/v1/smtp?");
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 404);
    host.policy_count = 1;
    host.policies[0].body_limit = 1024;
    host.route_count = 4;
    strcpy(host.routes[1].method, "GET"); strcpy(host.routes[1].path, "/admin/");
    host.routes[1].prefix = host.routes[1].query = host.routes[1].challenge = 1;
    host.routes[1].policy_index = 1;
    strcpy(host.routes[2].method, "POST"); strcpy(host.routes[2].path, "/admin/strict");
    host.routes[2].policy_index = 1;
    strcpy(host.routes[3].method, "POST"); strcpy(host.routes[3].path, "/admin/deep/");
    host.routes[3].prefix = 1;
    request.content_length = 0;
    strcpy(request.target, "/admin/file?next=%2Ftest&empty=");
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 0 && route == 1);
    request.content_length = 1025;
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 413);
    request.content_length = 0;
    strcpy(request.target, "/admin/strict");
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 405);
    strcpy(request.method, "POST"); strcpy(request.target, "/admin/strict?x=1");
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 404);
    strcpy(request.target, "/admin/deep/file");
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 0 && route == 3);
    strcpy(request.method, "GET");
    assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 405);
    {
        const char *paths[] = {"/administer/", "/admin", "/admin/a/..", "/admin/a/.",
                              "/admin/%2fprivate", "/admin/a\\b", "/admin//a"};
        for (i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
            strcpy(request.target, paths[i]);
            assert(ankah_host_request(&host, &request, "submit.example", 0, &route) == 404);
        }
    }
    assert(ankah_host_policy(&host, 1) == &host.policies[0]);
    assert(ankah_host_policy(&host, 3) == &host.defaults);
    assert(!ankah_host_route_conflict(&host, 1));
    strcpy(host.dashboard_route, "/admin/");
    assert(ankah_host_route_conflict(&host, 1));
    host.dashboard_route[0] = 0;
    {
        ankah_static_entry entry = {0};
        entry.url = "/admin/file"; host.bundle.entries = &entry; host.bundle.count = 1;
        assert(ankah_host_route_conflict(&host, 1));
        host.bundle.entries = NULL; host.bundle.count = 0;
    }
    ankah_queue_limits(100, 200);
    assert(ankah_queue_reserve(0, 100) == 0);
    assert(ankah_queue_reserve(0, 1) < 0);
    assert(ankah_queue_reserve(1, 200) == 0);
    assert(ankah_queue_reserve(1, 1) < 0);
    ankah_queue_release(0, 100); ankah_queue_release(1, 200);
    assert(ankah_queue_current(0) == 0 && ankah_queue_current(1) == 0);
    assert(ankah_queue_peak(0) == 100 && ankah_queue_peak(1) == 200);
    assert(ankah_absolute_timeout_ms(0, 105000000000ULL, 115000000000ULL, 5000000000ULL) == 5000);
    assert(ankah_absolute_timeout_ms(100000000000ULL, 105000000000ULL, 115000000000ULL, 0) == 5000);
    assert(ankah_absolute_timeout_ms(105000000000ULL, 105000000000ULL, 115000000000ULL, 0) == 0);
    assert(ankah_absolute_timeout_ms(105000000000ULL, 0, 115000000000ULL, 0) == 10000);
    assert(ankah_absolute_timeout_ms(114999999999ULL, 0, 115000000000ULL, 0) == 1);
    assert(ankah_absolute_timeout_ms(115000000000ULL, 0, 115000000000ULL, 0) == 0);
    return 0;
}
