/*
 * expunge_poison.c — repro/regression test for the clib4.library Expunge
 * poisoning defect (libExpunge destroying clib4.resource BEFORE the
 * lib_OpenCnt check).
 *
 * Background: exec/ramlib invoke a library's Expunge vector on every
 * system-wide memory flush (any failed AllocMem, or an explicit
 * "Avail FLUSH"), regardless of open count.  A buggy libExpunge tears down
 * clib4.resource (children hashmap, fallback clib, SysV maps, shared wmem
 * allocator) first and only then notices the library is still open and
 * stays resident (LIBF_DELEXP).  From then on nothing recreates the
 * resource: libOpen() silently skips the whole per-process _clib4 setup yet
 * still returns success, and the next clib4 program dies before main() with
 * a DSI — DAR=0x1510, `stw r29,5392(r31)` with r31=NULL (offsetof
 * __WBenchMsg in struct _clib4), at clib4_start+0x20c.  System-wide until
 * reboot.
 *
 * Roles (argv-selected):
 *   expunge_poison sleeper [seconds]   Hold clib4.library open for
 *                                      [seconds] (default 120) and exit 0.
 *                                      Keeps lib_OpenCnt > 0 so a flush
 *                                      hits the delayed-expunge path.
 *   expunge_poison crasher             Deliberately dereference NULL and
 *                                      crash (DSI).  Left GR-suspended it
 *                                      mirrors the field case: the wedged
 *                                      process holds lib_OpenCnt forever,
 *                                      so the delayed expunge (which would
 *                                      reload + libInit and recreate the
 *                                      resource) never completes.  Needs
 *                                      Grim Reaper / reboot to clean up —
 *                                      only use in a throwaway session.
 *   expunge_poison probe               Report whether this (fresh) process
 *                                      got a working clib4 context: prints
 *                                      clib4.resource presence and its own
 *                                      pr_UID, then PASS/FAIL.  On an
 *                                      unfixed library the probe never gets
 *                                      here — it DSIs in clib4_start.
 *
 * Driver logic (orchestrated guest-side from a Shell; kept as comments
 * because the flush and the crash recovery cannot be scripted portably
 * from inside a clib4 process):
 *
 *   ; --- poisoning repro (unfixed: step 3 DSIs; fixed: PASS) ---
 *   ; 1> Run >NIL: expunge_poison sleeper 120
 *   ;    (optionally also: Run >NIL: expunge_poison crasher — leave it
 *   ;     suspended in Grim Reaper to pin lib_OpenCnt like the field case)
 *   ; 2> Avail FLUSH
 *   ;    (fires libExpunge while the sleeper holds the library open)
 *   ; 3> expunge_poison probe
 *   ;    unfixed: DSI DAR=0x1510, stw r29,5392(r31), clib4_start+0x20c
 *   ;    fixed:   "PASS", resource present, pr_UID non-zero
 *   ;
 *   ; --- regression: true expunge must still work ---
 *   ; 4> wait for the sleeper to exit (and no other clib4 program running)
 *   ; 5> Avail FLUSH        ; must now fully expunge the library
 *   ; 6> expunge_poison probe
 *   ;    must reload + libInit cleanly: "PASS" again
 */

#define __USE_INLINE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <dos/dosextens.h>

#define DEFAULT_SLEEP_SECONDS 120

static int
do_sleeper(int seconds)
{
    printf("sleeper: holding clib4.library open for %d seconds (pid %lu)\n",
           seconds, (unsigned long) GetPID(0, GPID_PROCESS));
    fflush(stdout);

    /* Sleep in 1-second slices so Ctrl-C can end the test early. */
    for (int i = 0; i < seconds; i++)
        sleep(1);

    printf("sleeper: done, exiting cleanly\n");
    return EXIT_SUCCESS;
}

static int
do_crasher(void)
{
    printf("crasher: about to dereference NULL (leave me GR-suspended "
           "to pin lib_OpenCnt)\n");
    fflush(stdout);

    *(volatile unsigned long *) 0 = 0x0BADC0DEUL;

    /* Not reached. */
    printf("crasher: survived?! (should have crashed)\n");
    return EXIT_FAILURE;
}

static int
do_probe(void)
{
    /* Reaching this point at all is already most of the test: on an
     * unfixed library a post-flush launch DSIs inside clib4_start before
     * main().  Double-check the per-process state anyway. */
    struct Process *me = (struct Process *) FindTask(NULL);
    APTR res = OpenResource("clib4.resource");
    int ok = 1;

    printf("probe: clib4.resource = %p\n", res);
    printf("probe: pr_UID (per-process _clib4) = 0x%08lx\n",
           (unsigned long) me->pr_UID);

    if (res == NULL) {
        printf("probe: FAIL - clib4.resource is gone (expunge poisoning)\n");
        ok = 0;
    }
    if (me->pr_UID == 0) {
        printf("probe: FAIL - no per-process _clib4 (libOpen half-succeeded)\n");
        ok = 0;
    }

    if (ok)
        printf("PASS\n");

    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void
usage(const char *self)
{
    printf("Usage: %s sleeper [seconds] | crasher | probe\n", self);
    printf("  sleeper  hold clib4.library open (default %d s)\n",
           DEFAULT_SLEEP_SECONDS);
    printf("  crasher  crash with a DSI (WARNING: needs Grim Reaper/reboot)\n");
    printf("  probe    verify this process got a valid clib4 context\n");
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "sleeper") == 0) {
        int seconds = DEFAULT_SLEEP_SECONDS;
        if (argc > 2) {
            seconds = atoi(argv[2]);
            if (seconds <= 0)
                seconds = DEFAULT_SLEEP_SECONDS;
        }
        return do_sleeper(seconds);
    }

    if (strcmp(argv[1], "crasher") == 0)
        return do_crasher();

    if (strcmp(argv[1], "probe") == 0)
        return do_probe();

    usage(argv[0]);
    return EXIT_FAILURE;
}
