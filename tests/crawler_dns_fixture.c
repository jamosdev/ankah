#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

#define FIXTURE_IP "203.0.113.42"
#define FIXTURE_HOST "crawler.search.msn.com"

int getnameinfo(const struct sockaddr *address, socklen_t address_length,
                char *host, socklen_t host_length, char *service,
                socklen_t service_length, int flags) {
    static int (*original)(const struct sockaddr *, socklen_t, char *, socklen_t,
                           char *, socklen_t, int);
    struct in_addr expected;
    (void)address_length;
    (void)flags;
    inet_pton(AF_INET, FIXTURE_IP, &expected);
    if (address && address->sa_family == AF_INET &&
        memcmp(&((const struct sockaddr_in *)address)->sin_addr, &expected,
               sizeof(expected)) == 0) {
        if (host_length <= strlen(FIXTURE_HOST)) return EAI_OVERFLOW;
        strcpy(host, FIXTURE_HOST);
        if (service && service_length) service[0] = 0;
        return 0;
    }
    if (!original) original = dlsym(RTLD_NEXT, "getnameinfo");
    return original(address, address_length, host, host_length,
                    service, service_length, flags);
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **result) {
    static int (*original)(const char *, const char *, const struct addrinfo *,
                           struct addrinfo **);
    struct addrinfo *answer;
    struct sockaddr_in *address;
    if (!node || strcmp(node, FIXTURE_HOST) != 0) {
        if (!original) original = dlsym(RTLD_NEXT, "getaddrinfo");
        return original(node, service, hints, result);
    }
    answer = calloc(1, sizeof(*answer));
    address = calloc(1, sizeof(*address));
    if (!answer || !address) {
        free(answer);
        free(address);
        return EAI_MEMORY;
    }
    address->sin_family = AF_INET;
    inet_pton(AF_INET, FIXTURE_IP, &address->sin_addr);
    answer->ai_family = AF_INET;
    answer->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
    answer->ai_addrlen = sizeof(*address);
    answer->ai_addr = (struct sockaddr *)address;
    *result = answer;
    return 0;
}
