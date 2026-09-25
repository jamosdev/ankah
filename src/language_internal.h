#ifndef ANKAH_LANGUAGE_INTERNAL_H
#define ANKAH_LANGUAGE_INTERNAL_H

#include "ankah/language.h"

typedef const char *(*ankah_language_text_lookup)(ankah_language language,
                                                  const char *name);

const char *ankah_language_text(ankah_language language, const char *name);
const char *ankah_language_message(ankah_language language, const char *english);
int ankah_language_render_html(ankah_language language, const unsigned char *input,
                               size_t input_size, unsigned char *output,
                               size_t output_size, size_t *written,
                               ankah_language_text_lookup lookup);

#endif
