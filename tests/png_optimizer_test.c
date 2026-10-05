#include "png_optimizer.h"
#include "png_memory.h"
#include "lodepng.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *source_png(const unsigned char *rgba, unsigned w, unsigned h,
                                 size_t *size, unsigned depth) {
    LodePNGState state;
    unsigned char *png = NULL;
    lodepng_state_init(&state);
    state.info_raw.bitdepth = state.info_png.color.bitdepth = depth;
    state.encoder.auto_convert = 0;
    state.encoder.zlibsettings.btype = 0;
    assert(!lodepng_encode(&png, size, rgba, w, h, &state));
    lodepng_state_cleanup(&state);
    return png;
}

static void check_exact(unsigned colors, unsigned width, unsigned height) {
    size_t pixels = (size_t)width * height, size, optimized_size, i;
    unsigned char *rgba = malloc(pixels * 4), *png, *optimized, *decoded;
    unsigned w, h;
    assert(rgba);
    for (i = 0; i < pixels; ++i) {
        unsigned value = (unsigned)i % colors;
        rgba[i * 4] = (unsigned char)value;
        rgba[i * 4 + 1] = (unsigned char)(value * 3);
        rgba[i * 4 + 2] = (unsigned char)(value * 7);
        rgba[i * 4 + 3] = (unsigned char)(value ? value % 3 == 0 ? 128 : 255 : 0);
    }
    png = source_png(rgba, width, height, &size, 8);
    assert(ankah_png_optimize(png, size, ANKAH_PNG_MEMORY_LIMIT,
                              &optimized, &optimized_size) == 1);
    assert(optimized_size < size && optimized[25] == 3 && optimized[28] == 1);
    assert(!lodepng_decode32(&decoded, &w, &h, optimized, optimized_size));
    assert(w == width && h == height && !memcmp(rgba, decoded, pixels * 4));
    assert(ankah_png_memory_used() == 0);
    ankah_png_free(decoded);
    ankah_png_free(png);
    free(optimized);
    free(rgba);
}

static void check_quantization(void) {
    unsigned char rgba[32 * 32 * 4], *png, *optimized, *decoded;
    unsigned w, h, i, levels[256] = {0}, count = 0;
    size_t size, optimized_size;
    static const size_t limits[] = {
        0, 1, 8192, 32768, 65536, 524288, 550000, 570000, 600000, 640000, 700000
    };
    for (i = 0; i < 32 * 32; ++i) {
        rgba[i * 4] = (unsigned char)i;
        rgba[i * 4 + 1] = (unsigned char)(i >> 2);
        rgba[i * 4 + 2] = (unsigned char)(i * 17);
        rgba[i * 4 + 3] = (unsigned char)(i % 4 == 0 ? 0 : i % 4 == 1 ? 128 : 255);
    }
    png = source_png(rgba, 32, 32, &size, 8);
    assert(ankah_png_optimize(png, size, ANKAH_PNG_MEMORY_LIMIT,
                              &optimized, &optimized_size) == 1);
    assert(optimized_size < size && optimized[25] == 3 && optimized[28] == 1);
    assert(!lodepng_decode32(&decoded, &w, &h, optimized, optimized_size));
    assert(w == 32 && h == 32);
    for (i = 0; i < 32 * 32; ++i) {
        if (!rgba[i * 4 + 3]) assert(!decoded[i * 4 + 3]);
        levels[decoded[i * 4 + 3]] = 1;
    }
    for (i = 0; i < 256; ++i) count += levels[i];
    assert(count > 2);
    ankah_png_free(decoded);
    free(optimized);
    /* Budgets exercise failure before decode, during decode, and during
     * histogram construction. No failure may leak or return partial output. */
    for (i = 0; i < sizeof(limits) / sizeof(limits[0]); ++i) {
        int result = ankah_png_optimize(png, size, limits[i], &optimized, &optimized_size);
        assert(ankah_png_memory_used() == 0);
        if (result) free(optimized);
        else assert(!optimized && !optimized_size);
    }
    ankah_png_free(png);
}

static void check_passthrough(void) {
    unsigned char rgba[8] = {0}, *png, *optimized;
    unsigned char *chunk = NULL, *profiled;
    unsigned char profile[4] = {1, 13, 0, 1};
    size_t size, optimized_size, chunk_size = 0;
    png = source_png(rgba, 1, 1, &size, 8);
    /* An already tiny image must retain its original encoding on no saving. */
    assert(!ankah_png_optimize(png, size, ANKAH_PNG_MEMORY_LIMIT,
                               &optimized, &optimized_size));
    assert(!optimized && !optimized_size);
    assert(!ankah_png_optimize(png, size - 1, ANKAH_PNG_MEMORY_LIMIT,
                               &optimized, &optimized_size));
    png[45] ^= 1; /* Corrupt the compressed image or its checksum. */
    assert(!ankah_png_optimize(png, size, ANKAH_PNG_MEMORY_LIMIT,
                               &optimized, &optimized_size));
    png[45] ^= 1;
    assert(!lodepng_chunk_create(&chunk, &chunk_size, 4, "cICP", profile));
    profiled = malloc(size + chunk_size);
    assert(profiled);
    memcpy(profiled, png, 33);
    memcpy(profiled + 33, chunk, chunk_size);
    memcpy(profiled + 33 + chunk_size, png + 33, size - 33);
    assert(!ankah_png_optimize(profiled, size + chunk_size, ANKAH_PNG_MEMORY_LIMIT,
                               &optimized, &optimized_size));
    memcpy(profiled + 37, "acTL", 4);
    lodepng_chunk_generate_crc(profiled + 33);
    assert(!ankah_png_optimize(profiled, size + chunk_size, ANKAH_PNG_MEMORY_LIMIT,
                               &optimized, &optimized_size));
    free(profiled);
    ankah_png_free(chunk);
    ankah_png_free(png);
    png = source_png(rgba, 1, 1, &size, 16);
    assert(!ankah_png_optimize(png, size, ANKAH_PNG_MEMORY_LIMIT,
                               &optimized, &optimized_size));
    ankah_png_free(png);
    assert(!ankah_png_optimize(NULL, 0, ANKAH_PNG_MEMORY_LIMIT,
                               &optimized, &optimized_size));
    assert(!ankah_png_memory_used());
}

static void check_hidden_colors(void) {
    unsigned char rgba[1024 * 4], *png, *optimized, *decoded;
    unsigned i, w, h;
    size_t size, optimized_size;
    for (i = 0; i < 1024; ++i) {
        rgba[i * 4] = (unsigned char)i;
        rgba[i * 4 + 1] = (unsigned char)(i >> 8);
        rgba[i * 4 + 2] = 0;
        rgba[i * 4 + 3] = 0;
    }
    /* More than 256 hidden RGB values, but only one visible colour. */
    rgba[3] = 255;
    png = source_png(rgba, 32, 32, &size, 8);
    assert(ankah_png_optimize(png, size, ANKAH_PNG_MEMORY_LIMIT,
                              &optimized, &optimized_size) == 1);
    assert(!lodepng_decode32(&decoded, &w, &h, optimized, optimized_size));
    assert(decoded[3] == 255);
    for (i = 1; i < 1024; ++i) assert(!decoded[i * 4 + 3]);
    ankah_png_free(decoded);
    free(optimized);
    ankah_png_free(png);
    rgba[3] = 0;
    png = source_png(rgba, 32, 32, &size, 8);
    assert(!ankah_png_optimize(png, size, ANKAH_PNG_MEMORY_LIMIT,
                               &optimized, &optimized_size));
    ankah_png_free(png);
}

int main(void) {
    check_exact(1, 33, 17);
    check_exact(2, 33, 17);
    check_exact(4, 33, 17);
    check_exact(16, 33, 17);
    check_exact(256, 33, 17);
    check_quantization();
    check_passthrough();
    check_hidden_colors();
    puts("PNG optimizer checks passed");
    return 0;
}
