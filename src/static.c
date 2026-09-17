#include "ankah/static.h"
#include "ankah/http.h"

#include "ankah/sha256.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_STATIC_FILES 100000

static uint64_t hash_url(const char *url) {
    uint64_t result = UINT64_C(14695981039346656037);
    while (*url) {
        result ^= (unsigned char)*url++;
        result *= UINT64_C(1099511628211);
    }
    return result;
}

static int digest_name(const char *name) {
    size_t i;
    if (strlen(name) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((name[i] >= '0' && name[i] <= '9') ||
              (name[i] >= 'a' && name[i] <= 'f'))) return 0;
    return 1;
}

static int valid_prefix(const char *prefix) {
    size_t length = strlen(prefix), i;
    if (!length || prefix[0] != '/' || prefix[length - 1] != '/' ||
        strncmp(prefix, "/ankah/", 7) == 0) return 0;
    for (i = 0; i < length; ++i)
        if ((unsigned char)prefix[i] < 33 || (unsigned char)prefix[i] > 126 ||
            prefix[i] == '?' || prefix[i] == '#' || prefix[i] == '%' ||
            prefix[i] == '\\' || (i && prefix[i] == '/' && prefix[i - 1] == '/'))
            return 0;
    return 1;
}

static int parse_entry(ankah_static_entry *entry, char *line,
                       const char *directory, const char *prefix) {
    char *fields[5], *cursor = line, *separator, *end;
    char path[4096];
    struct stat metadata;
    unsigned char digest[32];
    size_t i;
    unsigned long long declared_size;
    int descriptor, length;
    void *mapping = NULL;
    for (i = 0; i < 4; ++i) {
        fields[i] = cursor;
        separator = strchr(cursor, '\t');
        if (!separator) return -1;
        *separator = 0;
        cursor = separator + 1;
    }
    fields[4] = cursor;
    if (strchr(cursor, '\t') || !digest_name(fields[1]) ||
        !fields[0][0] || strlen(fields[0]) >= ANKAH_MAX_TARGET ||
        strncmp(fields[0], prefix, strlen(prefix)) != 0 ||
        strchr(fields[0], '?') || strchr(fields[0], '#') ||
        strchr(fields[0], '\r') || strchr(fields[0], '\n') ||
        !fields[2][0] || !fields[3][0] || strlen(fields[3]) > 128 ||
        strchr(fields[3], '\r') || strchr(fields[3], '\n') ||
        (strcmp(fields[4], "0") != 0 && strcmp(fields[4], "1") != 0)) return -1;
    errno = 0;
    declared_size = strtoull(fields[2], &end, 10);
    if (errno || *end || declared_size > SIZE_MAX) return -1;
    length = snprintf(path, sizeof(path), "%s/files/%s", directory, fields[1]);
    if (length < 0 || (size_t)length >= sizeof(path)) return -1;
    descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size < 0 || (uint64_t)metadata.st_size != declared_size) {
        close(descriptor);
        return -1;
    }
    if (declared_size) {
        mapping = mmap(NULL, (size_t)declared_size, PROT_READ, MAP_PRIVATE, descriptor, 0);
        if (mapping == MAP_FAILED) { close(descriptor); return -1; }
    }
    close(descriptor);
    if (ankah_sha256(declared_size ? mapping : "", (size_t)declared_size,
                     digest) != 0) {
        if (mapping) munmap(mapping, (size_t)declared_size);
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        static const char hex[] = "0123456789abcdef";
        if (fields[1][i * 2] != hex[digest[i] >> 4] ||
            fields[1][i * 2 + 1] != hex[digest[i] & 15]) {
            if (mapping) munmap(mapping, (size_t)declared_size);
            return -1;
        }
    }
    entry->url = strdup(fields[0]);
    entry->mime = strdup(fields[3]);
    if (!entry->url || !entry->mime) {
        free(entry->url);
        free(entry->mime);
        if (mapping) munmap(mapping, (size_t)declared_size);
        return -1;
    }
    entry->data = mapping;
    entry->size = (size_t)declared_size;
    entry->immutable = fields[4][0] == '1';
    entry->etag[0] = '"';
    memcpy(entry->etag + 1, fields[1], 64);
    entry->etag[65] = '"';
    entry->etag[66] = 0;
    return 0;
}

void ankah_static_free(ankah_static_bundle *bundle) {
    size_t i;
    if (!bundle) return;
    for (i = 0; i < bundle->count; ++i) {
        free(bundle->entries[i].url);
        free(bundle->entries[i].mime);
        if (bundle->entries[i].data)
            munmap(bundle->entries[i].data, bundle->entries[i].size);
    }
    free(bundle->entries);
    free(bundle->slots);
    free(bundle->prefix);
    memset(bundle, 0, sizeof(*bundle));
}

int ankah_static_load(ankah_static_bundle *bundle, const char *directory) {
    char path[4096], *line = NULL;
    size_t line_capacity = 0, capacity = 0, i;
    ssize_t read_size;
    FILE *file = NULL;
    int length, result = -1;
    memset(bundle, 0, sizeof(*bundle));
    length = snprintf(path, sizeof(path), "%s/manifest.tsv", directory);
    if (length < 0 || (size_t)length >= sizeof(path)) return -1;
    file = fopen(path, "rb");
    if (!file) return -1;
    read_size = getline(&line, &line_capacity, file);
    if (read_size < 0 || read_size > ANKAH_MAX_TARGET + 32 ||
        memchr(line, 0, (size_t)read_size) ||
        line[read_size - 1] != '\n' ||
        strncmp(line, "ANKAH_STATIC_V1\t", 16) != 0) goto done;
    line[read_size - 1] = 0;
    bundle->prefix = strdup(line + 16);
    if (!bundle->prefix || !valid_prefix(bundle->prefix)) goto done;
    while ((read_size = getline(&line, &line_capacity, file)) >= 0) {
        ankah_static_entry *next;
        if (read_size > 4096 || memchr(line, 0, (size_t)read_size) ||
            line[read_size - 1] != '\n' ||
            bundle->count >= MAX_STATIC_FILES) goto done;
        line[read_size - 1] = 0;
        if (bundle->count == capacity) {
            size_t new_capacity = capacity ? capacity * 2 : 32;
            next = realloc(bundle->entries, new_capacity * sizeof(*next));
            if (!next) goto done;
            bundle->entries = next;
            capacity = new_capacity;
        }
        memset(&bundle->entries[bundle->count], 0, sizeof(*bundle->entries));
        if (parse_entry(&bundle->entries[bundle->count], line, directory,
                        bundle->prefix) != 0) goto done;
        ++bundle->count;
    }
    if (ferror(file)) goto done;
    bundle->slot_count = 32;
    while (bundle->slot_count < bundle->count * 2) bundle->slot_count *= 2;
    bundle->slots = calloc(bundle->slot_count, sizeof(*bundle->slots));
    if (!bundle->slots) goto done;
    for (i = 0; i < bundle->count; ++i) {
        size_t slot = (size_t)hash_url(bundle->entries[i].url) & (bundle->slot_count - 1);
        while (bundle->slots[slot]) {
            if (strcmp(bundle->entries[bundle->slots[slot] - 1].url,
                       bundle->entries[i].url) == 0) goto done;
            slot = (slot + 1) & (bundle->slot_count - 1);
        }
        bundle->slots[slot] = i + 1;
    }
    result = 0;
done:
    free(line);
    fclose(file);
    if (result != 0) ankah_static_free(bundle);
    return result;
}

const ankah_static_entry *ankah_static_find(const ankah_static_bundle *bundle,
                                             const char *url) {
    size_t slot;
    if (!bundle->slots) return NULL;
    slot = (size_t)hash_url(url) & (bundle->slot_count - 1);
    while (bundle->slots[slot]) {
        const ankah_static_entry *entry = &bundle->entries[bundle->slots[slot] - 1];
        if (strcmp(entry->url, url) == 0) return entry;
        slot = (slot + 1) & (bundle->slot_count - 1);
    }
    return NULL;
}

int ankah_static_in_namespace(const ankah_static_bundle *bundle, const char *url) {
    return bundle->prefix && strcmp(bundle->prefix, "/") != 0 &&
           strncmp(url, bundle->prefix, strlen(bundle->prefix)) == 0;
}
