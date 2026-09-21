#include "header_names.h"
#include <string.h>

int ankah_header_set_name(ankah_header *header, const char *name, size_t length) {
    unsigned char kind;
    if (!header || !name || !length || length >= ANKAH_MAX_FIELD ||
        memchr(name, 0, length)) return -1;
    kind = ankah_header_name_kind(name, length);
    memmove(header->name, name, length);
    header->name[length] = 0;
    header->kind = kind;
    return 0;
}
