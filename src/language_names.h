#ifndef ANKAH_LANGUAGE_NAMES_H
#define ANKAH_LANGUAGE_NAMES_H

#include "ankah/language.h"
#include <stddef.h>

struct ankah_language_keyword {
    const char *name;
    ankah_language language;
};

const struct ankah_language_keyword *ankah_language_lookup(const char *name,
                                                            size_t length);

#endif
