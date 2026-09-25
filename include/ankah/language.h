#ifndef ANKAH_LANGUAGE_H
#define ANKAH_LANGUAGE_H

#include "ankah/http.h"

typedef enum {
    ANKAH_LANGUAGE_EN,
    ANKAH_LANGUAGE_JA,
    ANKAH_LANGUAGE_ES,
    ANKAH_LANGUAGE_COUNT
} ankah_language;

ankah_language ankah_language_select(const ankah_request *request);
const char *ankah_language_tag(ankah_language language);

int ankah_language_log_open(const char *path);
void ankah_language_log_request(const ankah_request *request);
void ankah_language_log_close(void);

#endif
