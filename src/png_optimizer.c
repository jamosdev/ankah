/* Copyright (C) 2026 Jamosdev. Licensed under LGPL-3.0-or-later. */
#include "png_optimizer.h"
#include "png_memory.h"
#include "exoquant.h"
#include "lodepng.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static unsigned png_u32(const unsigned char *data) {
    return ((unsigned)data[0] << 24) | ((unsigned)data[1] << 16) |
           ((unsigned)data[2] << 8) | data[3];
}

static int supported_png(const unsigned char *input, size_t size) {
    static const unsigned char signature[8] = {137, 80, 78, 71, 13, 10, 26, 10};
    size_t at = 8;
    if (!input || size < 45 || size > 4U * 1024U * 1024U ||
        memcmp(input, signature, 8) || png_u32(input + 8) != 13 ||
        memcmp(input + 12, "IHDR", 4) || !png_u32(input + 16) ||
        !png_u32(input + 20) || png_u32(input + 16) > 1024 ||
        png_u32(input + 20) > 1024 || input[24] == 16) return 0;
    while (size - at >= 12) {
        size_t length = png_u32(input + at);
        const unsigned char *type = input + at + 4;
        if (length > size - at - 12) return 0;
        /* Avoid changing animation, profile interpretation or orientation. */
        if (!memcmp(type, "acTL", 4) || !memcmp(type, "iCCP", 4) ||
            !memcmp(type, "cICP", 4) || !memcmp(type, "eXIf", 4) ||
            !memcmp(type, "sBIT", 4)) return 0;
        at += length + 12;
        if (!memcmp(type, "IEND", 4)) return length == 0 && at == size;
    }
    return 0;
}

static unsigned exact_palette(const unsigned char *rgba, size_t pixels,
                               unsigned char *palette, unsigned char *indices) {
    size_t i;
    unsigned colors = 0;
    for (i = 0; i < pixels; ++i) {
        unsigned j;
        for (j = 0; j < colors; ++j)
            if (!memcmp(rgba + i * 4, palette + j * 4, 4)) break;
        if (j == colors) {
            if (colors == 256) return 0;
            memcpy(palette + colors * 4, rgba + i * 4, 4);
            ++colors;
        }
        indices[i] = (unsigned char)j;
    }
    return colors;
}

int ankah_png_optimize(const unsigned char *input, size_t input_size,
                       size_t memory_limit, unsigned char **output, size_t *output_size) {
    LodePNGState state;
    exq_data *quantizer = NULL;
    unsigned char palette[1024] = {0};
    unsigned char *rgba = NULL, *indices = NULL, *png = NULL;
    size_t pixels, png_size = 0, i;
    unsigned width, height, colors, error;
    int changed = 0, transparent = 0;
    if (!output || !output_size) return 0;
    *output = NULL;
    *output_size = 0;
    if (!supported_png(input, input_size)) return 0;
    if (memory_limit > ANKAH_PNG_MEMORY_LIMIT) memory_limit = ANKAH_PNG_MEMORY_LIMIT;
    ankah_png_memory_begin(memory_limit);
    lodepng_state_init(&state);
    state.decoder.read_text_chunks = 0;
    error = lodepng_decode(&rgba, &width, &height, &state, input, input_size);
    if (error) goto done;
    pixels = (size_t)width * height;
    indices = ankah_png_malloc(pixels);
    if (!indices) goto done;
    colors = exact_palette(rgba, pixels, palette, indices);
    if (!colors) {
        size_t start, visible = 0;
        quantizer = exq_init();
        if (!quantizer) goto done;
        /* Feed visible runs only. Fully transparent pixels get a reserved
         * entry rather than being averaged into almost-transparent colours. */
        for (i = 0; i < pixels;) {
            if (!rgba[i * 4 + 3]) { transparent = 1; ++i; continue; }
            start = i;
            while (i < pixels && rgba[i * 4 + 3]) ++i;
            visible += i - start;
            exq_feed(quantizer, rgba + start * 4, (int)(i - start));
            if (quantizer->failed) goto done;
        }
        if (!visible) goto done;
        exq_quantize_hq(quantizer, quantizer->histogramColors < 256 - transparent ?
            quantizer->histogramColors : 256 - transparent);
        colors = (unsigned)quantizer->numColors;
        exq_get_palette(quantizer, palette, (int)colors);
        exq_map_image(quantizer, (int)pixels, rgba, indices);
        if (transparent) {
            memset(palette + colors * 4, 0, 4);
            for (i = 0; i < pixels; ++i)
                if (!rgba[i * 4 + 3]) indices[i] = (unsigned char)colors;
            ++colors;
        }
        /* Drop unused entries and use first-pixel order for a stable palette
         * on subsequent uploads of this output, without further colour loss. */
        for (i = 0; i < pixels; ++i)
            memcpy(rgba + i * 4, palette + (size_t)indices[i] * 4, 4);
        colors = exact_palette(rgba, pixels, palette, indices);
    }
    state.encoder.auto_convert = 0;
    state.encoder.zlibsettings.windowsize = 32768;
    state.encoder.zlibsettings.nicematch = 258;
    state.info_png.interlace_method = 1;
    state.info_png.background_defined = 0;
    lodepng_color_mode_cleanup(&state.info_raw);
    lodepng_color_mode_cleanup(&state.info_png.color);
    lodepng_color_mode_init(&state.info_raw);
    lodepng_color_mode_init(&state.info_png.color);
    state.info_raw.colortype = state.info_png.color.colortype = LCT_PALETTE;
    state.info_raw.bitdepth = state.info_png.color.bitdepth =
        colors <= 2 ? 1 : colors <= 4 ? 2 : colors <= 16 ? 4 : 8;
    for (i = 0; i < colors; ++i) {
        const unsigned char *color = palette + i * 4;
        if (lodepng_palette_add(&state.info_raw, color[0], color[1], color[2], color[3]) ||
            lodepng_palette_add(&state.info_png.color, color[0], color[1], color[2], color[3]))
            goto done;
    }
    if (state.info_raw.bitdepth < 8) {
        unsigned bits = state.info_raw.bitdepth;
        /* PNG raw sub-byte input is packed continuously, without row padding. */
        for (i = 0; i < pixels; ++i) {
            size_t byte = i * bits / 8;
            unsigned shift = 8 - bits - (unsigned)(i * bits % 8);
            unsigned char value = indices[i];
            if (i * bits % 8 == 0) indices[byte] = 0;
            indices[byte] |= (unsigned char)(value << shift);
        }
    }
    error = lodepng_encode(&png, &png_size, indices, width, height, &state);
    if (!error && png_size < input_size && png_size <= memory_limit &&
        ankah_png_memory_used() <= memory_limit - png_size) {
        *output = malloc(png_size);
        if (*output) {
            memcpy(*output, png, png_size);
            *output_size = png_size;
            changed = 1;
        }
    }
done:
    if (quantizer) exq_free(quantizer);
    ankah_png_free(rgba);
    ankah_png_free(indices);
    ankah_png_free(png);
    lodepng_state_cleanup(&state);
    ankah_png_memory_end();
    return changed;
}
