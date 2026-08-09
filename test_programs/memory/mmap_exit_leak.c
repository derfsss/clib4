/*
 * mmap_exit_leak.c — verify that mmap() allocations which a process never
 * munmap()'s are reclaimed when the process exits (the stdlib_mmap_exit
 * destructor sweep in library/posix/mmap.c).
 *
 * Without the sweep, every AllocVecTags-backed mapping leaks until reboot:
 * AmigaOS has no per-process resource tracking for AllocVecTags memory, and
 * in the clib4.library build the __mmap_records list is system-global.
 *
 * Usage:
 *   mmap_exit_leak            parent: measures free memory, launches itself
 *                             as "mmap_exit_leak child" 3 times, re-measures.
 *                             PASS if free memory dropped by < 4 MB total.
 *   mmap_exit_leak child      child: mmap 64 MB anonymous, touch every page,
 *                             exit WITHOUT munmap.
 */

#define __USE_INLINE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <exec/memory.h>

#define CHILD_MMAP_SIZE (64UL * 1024UL * 1024UL) /* 64 MB */
#define PAGE_SIZE       4096UL
#define MAX_LEAK        (4UL * 1024UL * 1024UL)  /* 4 MB tolerance */
#define CHILD_RUNS      3

static int
run_child(const char *self)
{
    char cmd[512];
    LONG rc;

    snprintf(cmd, sizeof(cmd), "%s child", self);

    /* Synchronous launch; the child inherits our streams by default. */
    rc = SystemTags(cmd, TAG_DONE);
    return (int) rc;
}

int
main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        /* Child: leak a big anonymous mapping on purpose. */
        char *p = mmap(NULL, CHILD_MMAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("child: mmap(%lu) failed\n", CHILD_MMAP_SIZE);
            return 2;
        }

        /* Touch every page so the memory is really there. */
        for (unsigned long off = 0; off < CHILD_MMAP_SIZE; off += PAGE_SIZE)
            p[off] = (char) (off >> 12);

        printf("child: mapped and touched %lu MB, exiting without munmap\n",
               CHILD_MMAP_SIZE / (1024UL * 1024UL));
        /* Deliberately NO munmap: exit must reclaim it. */
        return 0;
    }

    /* Parent */
    ULONG before, after;
    long delta;
    int i;

    before = AvailMem(MEMF_ANY);
    printf("parent: free memory before: %lu bytes\n", (unsigned long) before);

    for (i = 1; i <= CHILD_RUNS; i++) {
        int rc = run_child(argv[0]);
        printf("parent: child run %d finished (rc=%d)\n", i, rc);
        if (rc != 0) {
            printf("FAIL: child run %d returned %d\n", i, rc);
            return 1;
        }
    }

    after = AvailMem(MEMF_ANY);
    delta = (long) before - (long) after;
    printf("parent: free memory after:  %lu bytes (delta %ld)\n",
           (unsigned long) after, delta);

    if (delta < (long) MAX_LEAK) {
        printf("PASS: %d x %lu MB child mappings were reclaimed at exit "
               "(net loss %ld bytes < %lu)\n",
               CHILD_RUNS, CHILD_MMAP_SIZE / (1024UL * 1024UL),
               delta, MAX_LEAK);
        return 0;
    }

    printf("FAIL: %ld bytes leaked across %d child runs "
           "(mmap records not swept at exit?)\n", delta, CHILD_RUNS);
    return 1;
}
