#include "ankah/qr.h"
#include "qrcodegen.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STBIW_ASSERT(value) ((void)(value))
#include "stb_image_write.h"

typedef struct {
    unsigned char *data;
    size_t length;
    size_t capacity;
    int failed;
} png_output;

static void append_png(void *context, void *data, int length) {
    png_output *out = (png_output *)context;
    unsigned char *next;
    size_t capacity;
    if (out->failed || length < 0 || (size_t)length > 65536 - out->length) {
        out->failed = 1;
        return;
    }
    if (out->length + (size_t)length > out->capacity) {
        capacity = out->capacity ? out->capacity * 2 : 4096;
        while (capacity < out->length + (size_t)length) capacity *= 2;
        next = realloc(out->data, capacity);
        if (!next) { out->failed = 1; return; }
        out->data = next;
        out->capacity = capacity;
    }
    memcpy(out->data + out->length, data, (size_t)length);
    out->length += (size_t)length;
}

int ankah_qr_png(const char *url, unsigned char **output, size_t *length) {
    uint8_t temp[qrcodegen_BUFFER_LEN_MAX], qr[qrcodegen_BUFFER_LEN_MAX];
    unsigned char *pixels;
    png_output out = {0};
    int modules, side, x, y;
    if (!url || !output || !length || strlen(url) > 512 ||
        !qrcodegen_encodeText(url, temp, qr, qrcodegen_Ecc_MEDIUM,
                              qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                              qrcodegen_Mask_AUTO, true)) return -1;
    modules = qrcodegen_getSize(qr);
    side = (modules + 8) * 6;
    pixels = malloc((size_t)side * (size_t)side);
    if (!pixels) return -1;
    for (y = 0; y < side; ++y) {
        for (x = 0; x < side; ++x) {
            int mx = x / 6 - 4, my = y / 6 - 4;
            pixels[(size_t)y * (size_t)side + (size_t)x] =
                mx >= 0 && my >= 0 && mx < modules && my < modules &&
                qrcodegen_getModule(qr, mx, my) ? 0 : 255;
        }
    }
    if (!stbi_write_png_to_func(append_png, &out, side, side, 1, pixels, side) || out.failed) {
        free(pixels);
        free(out.data);
        return -1;
    }
    free(pixels);
    *output = out.data;
    *length = out.length;
    return 0;
}
