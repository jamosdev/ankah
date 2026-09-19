#ifndef ANKAH_FILES_H
#define ANKAH_FILES_H

#include <stddef.h>
#include <time.h>

int ankah_file_read(const char *path, size_t maximum, int reject_links,
                    unsigned char **data, size_t *size, time_t *modified);
int ankah_file_map_exact(const char *path, size_t expected,
                         unsigned char **data);
void ankah_file_unmap(unsigned char *data, size_t size);

#endif
