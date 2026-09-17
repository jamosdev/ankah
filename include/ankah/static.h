#ifndef ANKAH_STATIC_H
#define ANKAH_STATIC_H

#include <stddef.h>

typedef struct {
    unsigned char *data;
    size_t size;
    char etag[67];
    int present;
} ankah_static_variant;

typedef struct {
    char *url;
    char *mime;
    ankah_static_variant variants[3];
    int immutable;
} ankah_static_entry;

typedef struct {
    char *prefix;
    ankah_static_entry *entries;
    size_t *slots;
    size_t count;
    size_t slot_count;
} ankah_static_bundle;

int ankah_static_load(ankah_static_bundle *bundle, const char *directory);
const ankah_static_entry *ankah_static_find(const ankah_static_bundle *bundle,
                                             const char *url);
int ankah_static_in_namespace(const ankah_static_bundle *bundle, const char *url);
void ankah_static_free(ankah_static_bundle *bundle);

#endif
