#ifndef ANKAH_PNG_MEMORY_H
#define ANKAH_PNG_MEMORY_H

#include <stddef.h>

/* The PNG codec and quantizer are private to the single mascot worker.
 * Begin/end delimit an allocation budget; calls must be serialized. */
void ankah_png_memory_begin(size_t limit);
size_t ankah_png_memory_used(void);
void ankah_png_memory_end(void);
void *ankah_png_malloc(size_t size);
void *ankah_png_realloc(void *pointer, size_t size);
void ankah_png_free(void *pointer);

#endif
