#ifndef ANKAH_PNG_OPTIMIZER_H
#define ANKAH_PNG_OPTIMIZER_H

#include <stddef.h>

#define ANKAH_PNG_MEMORY_LIMIT (64U * 1024U * 1024U)

/* Serialized calls only. Return 1 with a smaller malloc-owned output, or 0
 * to retain the input unchanged, including unsupported images and failures. */
int ankah_png_optimize(const unsigned char *input, size_t input_size,
                       size_t memory_limit, unsigned char **output, size_t *output_size);

#endif
