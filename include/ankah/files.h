#ifndef ANKAH_FILES_H
#define ANKAH_FILES_H

#include <stddef.h>
#include <time.h>

int ankah_file_read(const char *path, size_t maximum, int reject_links,
                    unsigned char **data, size_t *size, time_t *modified);
/* Returns 1 when the path does not exist, 0 on success, and -1 on error. */
int ankah_file_read_optional(const char *path, size_t maximum, int reject_links,
                             unsigned char **data, size_t *size);
int ankah_file_map_exact(const char *path, size_t expected,
                         unsigned char **data);
void ankah_file_unmap(unsigned char *data, size_t size);
/* Flushes temp_path and atomically replaces target_path with it. */
int ankah_file_replace(const char *temp_path, const char *target_path,
                       const unsigned char *data, size_t size);

#endif
