#include "png_memory.h"

#include <stdint.h>
#include <stdlib.h>

typedef union {
    struct { size_t size; int counted; } allocation;
    long double alignment;
    void *pointer_alignment;
} png_allocation;

static size_t memory_limit, memory_used;
static int budget_active;

void ankah_png_memory_begin(size_t limit) {
    memory_limit = limit;
    memory_used = 0;
    budget_active = 1;
}

size_t ankah_png_memory_used(void) { return memory_used; }

void ankah_png_memory_end(void) { budget_active = 0; }

void *ankah_png_malloc(size_t size) {
    png_allocation *allocation;
    size_t total;
    if (size > SIZE_MAX - sizeof(*allocation)) return NULL;
    total = size + sizeof(*allocation);
    if (budget_active && (total > memory_limit || memory_used > memory_limit - total))
        return NULL;
    allocation = malloc(total);
    if (!allocation) return NULL;
    allocation->allocation.size = total;
    allocation->allocation.counted = budget_active;
    if (budget_active) memory_used += total;
    return allocation + 1;
}

void ankah_png_free(void *pointer) {
    png_allocation *allocation;
    if (!pointer) return;
    allocation = (png_allocation *)pointer - 1;
    if (allocation->allocation.counted) memory_used -= allocation->allocation.size;
    free(allocation);
}

void *ankah_png_realloc(void *pointer, size_t size) {
    png_allocation *old, *allocation;
    size_t total, old_size;
    int counted;
    if (!pointer) return ankah_png_malloc(size);
    if (!size) { ankah_png_free(pointer); return NULL; }
    if (size > SIZE_MAX - sizeof(*allocation)) return NULL;
    old = (png_allocation *)pointer - 1;
    old_size = old->allocation.size;
    counted = old->allocation.counted;
    total = size + sizeof(*allocation);
    if (counted && (total > memory_limit || memory_used - old_size > memory_limit - total))
        return NULL;
    allocation = realloc(old, total);
    if (!allocation) return NULL;
    allocation->allocation.size = total;
    if (counted) memory_used = memory_used - old_size + total;
    return allocation + 1;
}

/* LodePNG's external allocator interface. */
void *lodepng_malloc(size_t size) { return ankah_png_malloc(size); }
void *lodepng_realloc(void *pointer, size_t size) { return ankah_png_realloc(pointer, size); }
void lodepng_free(void *pointer) { ankah_png_free(pointer); }
