#include "ankah/static.h"
#include "ankah/http.h"
#include "ankah/files.h"

#include "ankah/sha256.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static char *copy_text(const char *text) {
    size_t length = strlen(text) + 1;
    char *copy = (char *)malloc(length);
    if (copy) memcpy(copy, text, length);
    return copy;
}

static int read_line(FILE *file, char *line, size_t capacity, size_t *length) {
    size_t used = 0;
    int byte;
    while ((byte = fgetc(file)) != EOF) {
        if (byte == 0 || used + 1 >= capacity) return -1;
        if (byte == '\n') {
            line[used] = 0;
            *length = used + 1;
            return 1;
        }
        line[used++] = (char)byte;
    }
    if (ferror(file) || used) return -1;
    return 0;
}

static int parse_entry(ankah_static_entry *entry, char *line,
                       const char *directory, const char *prefix, int version) {
    char *fields[6], *cursor = line, *separator, *end;
    const char *digest_field, *size_field, *mime_field, *immutable_field;
    ankah_static_variant *variant;
    char path[4096];
    unsigned char digest[32];
    static const unsigned char empty = 0;
    size_t i;
    unsigned long long declared_size;
    int length, encoding = 0;
    unsigned char *mapping = NULL;
    for (i = 0; i < (version == 2 ? 5U : 4U); ++i) {
        fields[i] = cursor;
        separator = strchr(cursor, '\t');
        if (!separator) return -1;
        *separator = 0;
        cursor = separator + 1;
    }
    fields[version == 2 ? 5 : 4] = cursor;
    if (version == 2) {
        if (strcmp(fields[1], "gzip") == 0) encoding = 1;
        else if (strcmp(fields[1], "br") == 0) encoding = 2;
        else if (strcmp(fields[1], "identity") != 0) return -1;
    }
    digest_field = fields[version == 2 ? 2 : 1];
    size_field = fields[version == 2 ? 3 : 2];
    mime_field = fields[version == 2 ? 4 : 3];
    immutable_field = fields[version == 2 ? 5 : 4];
    variant = &entry->variants[encoding];
    if (strchr(cursor, '\t') || !digest_name(digest_field) ||
        !fields[0][0] || strlen(fields[0]) >= ANKAH_MAX_TARGET ||
        strncmp(fields[0], prefix, strlen(prefix)) != 0 ||
        strchr(fields[0], '?') || strchr(fields[0], '#') ||
        strchr(fields[0], '\r') || strchr(fields[0], '\n') ||
        !size_field[0] || !mime_field[0] || strlen(mime_field) > 128 ||
        strchr(mime_field, '\r') || strchr(mime_field, '\n') ||
        (strcmp(immutable_field, "0") != 0 && strcmp(immutable_field, "1") != 0) ||
        variant->present) return -1;
    if (entry->url && (strcmp(entry->url, fields[0]) != 0 ||
        strcmp(entry->mime, mime_field) != 0 ||
        entry->immutable != (immutable_field[0] == '1'))) return -1;
    errno = 0;
    declared_size = strtoull(size_field, &end, 10);
    if (errno || *end || declared_size > SIZE_MAX) return -1;
    length = snprintf(path, sizeof(path), "%s/files/%s", directory, digest_field);
    if (length < 0 || (size_t)length >= sizeof(path)) return -1;
    if (ankah_file_map_exact(path, (size_t)declared_size, &mapping) != 0)
        return -1;
    if (ankah_sha256(declared_size ? mapping : &empty, (size_t)declared_size,
                     digest) != 0) {
        ankah_file_unmap(mapping, (size_t)declared_size);
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        static const char hex[] = "0123456789abcdef";
        if (digest_field[i * 2] != hex[digest[i] >> 4] ||
            digest_field[i * 2 + 1] != hex[digest[i] & 15]) {
            ankah_file_unmap(mapping, (size_t)declared_size);
            return -1;
        }
    }
    if (!entry->url) {
        entry->url = copy_text(fields[0]);
        entry->mime = copy_text(mime_field);
        if (!entry->url || !entry->mime) {
            free(entry->url);
            free(entry->mime);
            entry->url = NULL;
            entry->mime = NULL;
            ankah_file_unmap(mapping, (size_t)declared_size);
            return -1;
        }
        entry->immutable = immutable_field[0] == '1';
    }
    variant->data = mapping;
    variant->size = (size_t)declared_size;
    variant->present = 1;
    variant->etag[0] = '"';
    memcpy(variant->etag + 1, digest_field, 64);
    variant->etag[65] = '"';
    variant->etag[66] = 0;
    return 0;
}

void ankah_static_free(ankah_static_bundle *bundle) {
    size_t i;
    if (!bundle) return;
    for (i = 0; i < bundle->count; ++i) {
        free(bundle->entries[i].url);
        free(bundle->entries[i].mime);
        for (int j = 0; j < 3; ++j)
            if (bundle->entries[i].variants[j].data)
                ankah_file_unmap(bundle->entries[i].variants[j].data,
                                 bundle->entries[i].variants[j].size);
    }
    free(bundle->entries);
    free(bundle->slots);
    free(bundle->prefix);
    memset(bundle, 0, sizeof(*bundle));
}

int ankah_static_load(ankah_static_bundle *bundle, const char *directory) {
    char path[4096], line[4098];
    size_t line_size, capacity = 0, i;
    FILE *file = NULL;
    int length, result = -1, version;
    memset(bundle, 0, sizeof(*bundle));
    length = snprintf(path, sizeof(path), "%s/manifest.tsv", directory);
    if (length < 0 || (size_t)length >= sizeof(path)) return -1;
    file = fopen(path, "rb");
    if (!file) return -1;
    if (read_line(file, line, sizeof(line), &line_size) != 1 ||
        line_size > ANKAH_MAX_TARGET + 32 ||
        (strncmp(line, "ANKAH_STATIC_V1\t", 16) != 0 &&
         strncmp(line, "ANKAH_STATIC_V2\t", 16) != 0)) goto done;
    version = line[14] == '2' ? 2 : 1;
    bundle->prefix = copy_text(line + 16);
    if (!bundle->prefix || !valid_prefix(bundle->prefix)) goto done;
    while ((length = read_line(file, line, sizeof(line), &line_size)) > 0) {
        ankah_static_entry *next;
        if (line_size > 4096) goto done;
        if (bundle->count == 0 || !bundle->entries[bundle->count - 1].url ||
            strncmp(line, bundle->entries[bundle->count - 1].url,
                    strlen(bundle->entries[bundle->count - 1].url)) != 0 ||
            line[strlen(bundle->entries[bundle->count - 1].url)] != '\t') {
          if (bundle->count >= MAX_STATIC_FILES ||
              (bundle->count && !bundle->entries[bundle->count - 1].variants[0].present))
              goto done;
          if (bundle->count == capacity) {
            size_t new_capacity = capacity ? capacity * 2 : 32;
            next = realloc(bundle->entries, new_capacity * sizeof(*next));
            if (!next) goto done;
            bundle->entries = next;
            capacity = new_capacity;
          }
          memset(&bundle->entries[bundle->count], 0, sizeof(*bundle->entries));
          ++bundle->count;
        }
        if (parse_entry(&bundle->entries[bundle->count - 1], line, directory,
                        bundle->prefix, version) != 0) goto done;
    }
    if (length < 0) goto done;
    if (bundle->count && !bundle->entries[bundle->count - 1].variants[0].present)
        goto done;
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
