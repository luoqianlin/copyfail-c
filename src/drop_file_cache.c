#define _POSIX_C_SOURCE 200112L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *path;
    int fd;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }

    path = argv[1];
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
        return 1;
    }

    /*
     * Flush dirty pages for this file if any exist, then ask the kernel to
     * evict this file's data pages from the page cache.
     */
    if (fsync(fd) < 0) {
        fprintf(stderr, "fsync(%s): %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }

    {
        int ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);

        if (ret != 0) {
            fprintf(stderr, "posix_fadvise(%s): %s\n", path, strerror(ret));
            close(fd);
            return 1;
        }
    }

    if (close(fd) < 0) {
        fprintf(stderr, "close(%s): %s\n", path, strerror(errno));
        return 1;
    }

    return 0;
}
