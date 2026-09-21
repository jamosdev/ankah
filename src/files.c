#include "ankah/files.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void erase_free(unsigned char *data, size_t size) {
    volatile unsigned char *cursor = data;
    while (size--) *cursor++ = 0;
    free(data);
}

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static int opened_as_requested(HANDLE file, const char *path) {
    char requested[32768], final[32768], unc[32768];
    const char *final_path = final;
    DWORD requested_size = GetFullPathNameA(path, sizeof(requested), requested, NULL);
    DWORD final_size = GetFinalPathNameByHandleA(file, final, sizeof(final),
                                                 FILE_NAME_NORMALIZED |
                                                 VOLUME_NAME_DOS);
    if (!requested_size || requested_size >= sizeof(requested) ||
        !final_size || final_size >= sizeof(final)) return 0;
    if (strncmp(final, "\\\\?\\UNC\\", 8) == 0) {
        size_t tail = strlen(final + 8);
        if (tail + 3 > sizeof(unc)) return 0;
        unc[0] = '\\';
        unc[1] = '\\';
        memcpy(unc + 2, final + 8, tail + 1);
        final_path = unc;
    } else if (strncmp(final, "\\\\?\\", 4) == 0) {
        final_path += 4;
    }
    return CompareStringA(LOCALE_INVARIANT, NORM_IGNORECASE,
                          requested, -1, final_path, -1) == CSTR_EQUAL;
}

static HANDLE open_regular(const char *path, int reject_links,
                           uint64_t *size, time_t *modified) {
    BY_HANDLE_FILE_INFORMATION information;
    ULARGE_INTEGER length, ticks;
    DWORD flags = FILE_ATTRIBUTE_NORMAL;
    HANDLE file;
    if (reject_links) flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       flags, NULL);
    if (file == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    if (!GetFileInformationByHandle(file, &information) ||
        (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (reject_links &&
         ((information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
          !opened_as_requested(file, path)))) {
        CloseHandle(file);
        return INVALID_HANDLE_VALUE;
    }
    length.HighPart = information.nFileSizeHigh;
    length.LowPart = information.nFileSizeLow;
    *size = length.QuadPart;
    if (modified) {
        ticks.HighPart = information.ftLastWriteTime.dwHighDateTime;
        ticks.LowPart = information.ftLastWriteTime.dwLowDateTime;
        *modified = ticks.QuadPart >= UINT64_C(116444736000000000)
            ? (time_t)((ticks.QuadPart - UINT64_C(116444736000000000)) /
                       UINT64_C(10000000))
            : (time_t)0;
    }
    return file;
}

int ankah_file_read(const char *path, size_t maximum, int reject_links,
                    unsigned char **data, size_t *size, time_t *modified) {
    uint64_t length;
    size_t used = 0;
    unsigned char *buffer;
    HANDLE file = open_regular(path, reject_links, &length, modified);
    if (file == INVALID_HANDLE_VALUE || length > maximum || length > SIZE_MAX - 1) {
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        return -1;
    }
    buffer = (unsigned char *)malloc((size_t)length + 1);
    if (!buffer) { CloseHandle(file); return -1; }
    while (used < (size_t)length) {
        DWORD amount = 0;
        size_t remaining = (size_t)length - used;
        DWORD request = remaining > UINT32_MAX ? UINT32_MAX : (DWORD)remaining;
        if (!ReadFile(file, buffer + used, request, &amount, NULL) || !amount) {
            erase_free(buffer, used);
            CloseHandle(file);
            return -1;
        }
        used += amount;
    }
    CloseHandle(file);
    buffer[used] = 0;
    *data = buffer;
    *size = used;
    return 0;
}

int ankah_file_read_optional(const char *path, size_t maximum, int reject_links,
                             unsigned char **data, size_t *size) {
    int result = ankah_file_read(path, maximum, reject_links, data, size, NULL);
    DWORD error;
    if (result == 0) return 0;
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) return -1;
    error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? 1 : -1;
}

int ankah_file_map_exact(const char *path, size_t expected,
                         unsigned char **data) {
    HANDLE mapping, file;
    uint64_t length;
    void *view;
    file = open_regular(path, 1, &length, NULL);
    if (file == INVALID_HANDLE_VALUE || length != expected) {
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        return -1;
    }
    if (!expected) { CloseHandle(file); *data = NULL; return 0; }
    mapping = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(file);
    if (!mapping) return -1;
    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, expected);
    CloseHandle(mapping);
    if (!view) return -1;
    *data = (unsigned char *)view;
    return 0;
}

void ankah_file_unmap(unsigned char *data, size_t size) {
    (void)size;
    if (data) UnmapViewOfFile(data);
}

int ankah_file_replace(const char *temp_path, const char *target_path,
                       const unsigned char *data, size_t size) {
    BY_HANDLE_FILE_INFORMATION information;
    HANDLE file = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    size_t used = 0;
    if (file == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileInformationByHandle(file, &information) ||
        (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                         FILE_ATTRIBUTE_REPARSE_POINT))) {
        CloseHandle(file);
        return -1;
    }
    while (used < size) {
        DWORD written = 0;
        size_t remaining = size - used;
        DWORD request = remaining > UINT32_MAX ? UINT32_MAX : (DWORD)remaining;
        if (!WriteFile(file, data + used, request, &written, NULL) || !written) {
            CloseHandle(file);
            return -1;
        }
        used += written;
    }
    if (!FlushFileBuffers(file)) { CloseHandle(file); return -1; }
    if (!CloseHandle(file)) return -1;
    return MoveFileExA(temp_path, target_path,
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : -1;
}

#else

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int open_regular(const char *path, int reject_links,
                        struct stat *metadata) {
    int flags = O_RDONLY;
    int descriptor;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    if (reject_links) flags |= O_NOFOLLOW;
#endif
    descriptor = open(path, flags);
    if (descriptor < 0 || fstat(descriptor, metadata) != 0 ||
        !S_ISREG(metadata->st_mode)) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
#ifndef O_NOFOLLOW
    if (reject_links) {
        struct stat link_metadata;
        if (lstat(path, &link_metadata) != 0 || S_ISLNK(link_metadata.st_mode)) {
            close(descriptor);
            return -1;
        }
    }
#endif
    return descriptor;
}

int ankah_file_read(const char *path, size_t maximum, int reject_links,
                    unsigned char **data, size_t *size, time_t *modified) {
    struct stat metadata;
    size_t used = 0;
    unsigned char *buffer;
    int descriptor = open_regular(path, reject_links, &metadata);
    if (descriptor < 0 || metadata.st_size < 0 ||
        (uint64_t)metadata.st_size > maximum ||
        (uint64_t)metadata.st_size > SIZE_MAX - 1) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    buffer = (unsigned char *)malloc((size_t)metadata.st_size + 1);
    if (!buffer) { close(descriptor); return -1; }
    while (used < (size_t)metadata.st_size) {
        ssize_t amount = read(descriptor, buffer + used,
                              (size_t)metadata.st_size - used);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            erase_free(buffer, used);
            close(descriptor);
            return -1;
        }
        used += (size_t)amount;
    }
    close(descriptor);
    buffer[used] = 0;
    if (modified) *modified = metadata.st_mtime;
    *data = buffer;
    *size = used;
    return 0;
}

int ankah_file_read_optional(const char *path, size_t maximum, int reject_links,
                             unsigned char **data, size_t *size) {
    struct stat metadata;
    int result = ankah_file_read(path, maximum, reject_links, data, size, NULL);
    if (result == 0) return 0;
    if (lstat(path, &metadata) == 0) return -1;
    return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}

int ankah_file_map_exact(const char *path, size_t expected,
                         unsigned char **data) {
    struct stat metadata;
    void *mapping;
    int descriptor = open_regular(path, 1, &metadata);
    if (descriptor < 0 || metadata.st_size < 0 ||
        (uint64_t)metadata.st_size != expected) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    if (!expected) { close(descriptor); *data = NULL; return 0; }
    mapping = mmap(NULL, expected, PROT_READ, MAP_PRIVATE, descriptor, 0);
    close(descriptor);
    if (mapping == MAP_FAILED) return -1;
    *data = (unsigned char *)mapping;
    return 0;
}

void ankah_file_unmap(unsigned char *data, size_t size) {
    if (data) munmap(data, size);
}

static void sync_parent(const char *path) {
    char directory[1024];
    const char *slash = strrchr(path, '/');
    size_t length;
    int descriptor, flags = O_RDONLY;
    if (!slash) {
        strcpy(directory, ".");
    } else {
        length = slash == path ? 1 : (size_t)(slash - path);
        if (length >= sizeof(directory)) return;
        memcpy(directory, path, length);
        directory[length] = 0;
    }
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    descriptor = open(directory, flags);
    if (descriptor >= 0) {
        (void)fsync(descriptor);
        close(descriptor);
    }
}

int ankah_file_replace(const char *temp_path, const char *target_path,
                       const unsigned char *data, size_t size) {
    struct stat metadata;
    size_t used = 0;
    int descriptor, flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#else
    {
        struct stat link_metadata;
        if (lstat(temp_path, &link_metadata) == 0) {
            if (S_ISLNK(link_metadata.st_mode)) return -1;
        } else if (errno != ENOENT && errno != ENOTDIR) return -1;
    }
#endif
    descriptor = open(temp_path, flags, S_IRUSR | S_IWUSR);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    while (used < size) {
        ssize_t amount = write(descriptor, data + used, size - used);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { close(descriptor); return -1; }
        used += (size_t)amount;
    }
    if (fsync(descriptor) != 0) { close(descriptor); return -1; }
    if (close(descriptor) != 0) return -1;
    if (rename(temp_path, target_path) != 0) return -1;
    sync_parent(target_path);
    return 0;
}

#endif
