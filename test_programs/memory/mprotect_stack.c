/*
 * mprotect_stack.c — stack-page mprotect() repro / bisection tool for
 * AmigaLabs/clib4 issue #431 (DSI, dar=0x70, when protecting pthread
 * stack pages — the pattern HotSpot uses for stack guard pages).
 *
 * Each case is selected by argv[1] so one crashing case cannot mask the
 * others.  Every syscall is bracketed by "MPROTEST [case] ..." marker
 * lines (flushed) so serial capture shows exactly which call died.
 *
 * Cases (run in this order — safe cases first):
 *   S6  control: mprotect on an mmap() page and a malloc'd heap page
 *       (must keep passing — regression guard for #431's retest result)
 *   S1  GetMemoryAttrs-ONLY probe (inline "mmu" interface — no library
 *       mprotect involved) on: AllocVecTags(MEMF_PRIVATE) page,
 *       AllocVecTags(MEMF_SHARED) page, main-task stack page, own
 *       pthread stack page.  The cheapest bisection: Get vs Set.
 *   S2  mprotect(own pthread stack low page, 4096, PROT_READ), restore
 *       PROT_READ|PROT_WRITE — byte-for-byte the HotSpot guard pattern
 *   S3  same with PROT_NONE, then restore — the actual JVM guard value
 *   S4  main (CLI) task stack page, same protect/restore sequence
 *   S5  from main, protect a parked sibling pthread's low stack page
 *       (the sibling sits in sem_wait)
 *   S7  THE DISCRIMINATOR for gate 2f / R-3, and SAFE (mmap page only, no
 *       stack): PROT_NONE round trip with the MMU attributes read back at
 *       each step.  Decides whether the restore failure is clib4's
 *       attrs==0 sentinel misreading a valid page, or the MMU refusing the
 *       transition.  Run this before S2/S3.
 *   S8  DANGEROUS, run LAST and alone: does GetMemoryAttrs distinguish an
 *       unmapped VA from a mapped PROT_NONE one?  Probes addresses we do
 *       not own and may DSI or suspend the task silently.
 *
 * Safety: only ever the LOWEST page of a stack is touched, far below the
 * live SP; it is restored immediately; nothing recurses between protect
 * and restore.
 */

#define __USE_INLINE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/mman.h>

#include <proto/exec.h>
#include <exec/memory.h>
#include <exec/tasks.h>
#include <interfaces/exec.h>

#define PAGE_SIZE 4096UL

#define MARK(case_name, fmt, ...) \
    do { \
        printf("MPROTEST [%s] " fmt "\n", case_name, ##__VA_ARGS__); \
        fflush(stdout); \
    } while (0)

static void *
page_align_up(void *p)
{
    return (void *) (((uintptr_t) p + PAGE_SIZE - 1) & ~(uintptr_t)(PAGE_SIZE - 1));
}

/* Low (deepest) page of the calling pthread's stack, from pthread_getattr_np:
 * stackaddr is the LOW end of the stack block. */
static void *
own_pthread_stack_low_page(void)
{
    pthread_attr_t attr;
    void *stackaddr = NULL;
    size_t stacksize = 0;

    if (pthread_getattr_np(pthread_self(), &attr) != 0)
        return NULL;
    if (pthread_attr_getstack(&attr, &stackaddr, &stacksize) != 0)
        return NULL;
    if (stackaddr == NULL || stacksize == 0)
        return NULL;
    return page_align_up(stackaddr);
}

static void *
thread_stack_low_page(pthread_t t)
{
    pthread_attr_t attr;
    void *stackaddr = NULL;
    size_t stacksize = 0;

    if (pthread_getattr_np(t, &attr) != 0)
        return NULL;
    if (pthread_attr_getstack(&attr, &stackaddr, &stacksize) != 0)
        return NULL;
    if (stackaddr == NULL || stacksize == 0)
        return NULL;
    return page_align_up(stackaddr);
}

static void *
main_task_stack_low_page(void)
{
    struct Task *me = FindTask(NULL);
    return page_align_up(me->tc_SPLower);
}

/* --------------------------------------------------------------------- */
/* Inline re-implementation of mprotect's MMU probe (GetMemoryAttrs only)
 * so Get-vs-Set and user-vs-supervisor can be bisected without library
 * rebuilds.  Returns 0 on success and stores the raw attrs.              */

static int
probe_attrs(const char *case_name, const char *what, void *addr, ULONG *out)
{
    struct MMUIFace *IMMU;
    APTR stack;
    ULONG attrs;

    MARK(case_name, "GetInterface(\"mmu\") for %s page %p", what, addr);
    IMMU = (struct MMUIFace *)
        GetInterface((struct Library *) IExec->Data.LibBase, "mmu", 1, NULL);
    if (IMMU == NULL) {
        MARK(case_name, "GetInterface(\"mmu\") FAILED");
        return -1;
    }

    MARK(case_name, "before SuperState + GetMemoryAttrs(%p, 0) [%s]", addr, what);
    stack = SuperState();
    /* NOTE: with __USE_INLINE__, GetMemoryAttrs() is a macro expanding to
     * IMMU->GetMemoryAttrs(...) against the local IMMU variable above. */
    attrs = GetMemoryAttrs(addr, 0);
    if (stack != NULL)
        UserState(stack);
    MARK(case_name, "after GetMemoryAttrs(%p) [%s] -> attrs=0x%08lx",
         addr, what, (unsigned long) attrs);

    DropInterface((struct Interface *) IMMU);
    *out = attrs;
    return 0;
}

/* One mprotect() call, with errno captured and reported.
 *
 * errno is reported on EVERY call, not only the failing ones: a run where
 * rc=0 and errno is untouched is the baseline that makes a reported errno
 * on the failing call interpretable.  Two things make that honest:
 *
 *   1. errno is CLEARED before the call.  POSIX only guarantees errno is
 *      meaningful after a failure, so on success it otherwise holds
 *      whatever the last failing libc call in this process left there --
 *      printing that would be a plausible wrong answer, which is worse
 *      than printing nothing.
 *   2. errno is SAVED into a local immediately after the call, before the
 *      printf.  printf/fflush are libc calls and may set errno themselves.
 *
 * Reported as both the number and strerror(), because the number alone is
 * not portable reading across a serial log and strerror() alone loses the
 * distinction if clib4 has no string for the value.
 */
static int
mprotect_reported(const char *case_name, const char *what, void *addr,
                  int prot, const char *prot_name, const char *phase)
{
    int rc, saved_errno;

    MARK(case_name, "before %s mprotect(%p, %lu, %s) [%s]",
         phase, addr, PAGE_SIZE, prot_name, what);

    errno = 0;
    rc = mprotect(addr, PAGE_SIZE, prot);
    saved_errno = errno;

    MARK(case_name, "after %s mprotect(%p, %s) [%s] -> rc=%d errno=%d (%s)",
         phase, addr, prot_name, what, rc, saved_errno,
         strerror(saved_errno));

    return rc;
}

/* mprotect + restore with markers around each call.  The restore is
 * applied whether or not the first call succeeded (best effort).         */
static int
protect_restore(const char *case_name, const char *what, void *addr,
                int prot, const char *prot_name)
{
    int rc1, rc2;

    rc1 = mprotect_reported(case_name, what, addr, prot, prot_name, "apply");
    rc2 = mprotect_reported(case_name, what, addr, PROT_READ | PROT_WRITE,
                            "PROT_READ|PROT_WRITE", "restore");

    return (rc1 == 0 && rc2 == 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ S6 */

static int
run_s6(void)
{
    int result = 0;

    MARK("S6", "start (control: mmap + heap pages)");

    void *m = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        MARK("S6", "mmap FAILED");
        return 1;
    }
    if (protect_restore("S6", "mmap", m, PROT_READ, "PROT_READ") != 0)
        result = 1;
    munmap(m, PAGE_SIZE);

    char *h = malloc(3 * PAGE_SIZE);
    if (h == NULL) {
        MARK("S6", "malloc FAILED");
        return 1;
    }
    void *hp = page_align_up(h);
    if (protect_restore("S6", "heap", hp, PROT_READ, "PROT_READ") != 0)
        result = 1;
    free(h);

    MARK("S6", "%s", result == 0 ? "PASS" : "FAIL");
    return result;
}

/* ------------------------------------------------------------------ S1 */

static void *
s1_thread(void *arg)
{
    (void) arg;
    ULONG attrs = 0;
    void *page = own_pthread_stack_low_page();

    if (page == NULL) {
        MARK("S1", "own pthread stack page lookup FAILED");
        return (void *) 1;
    }
    if (probe_attrs("S1", "pthread-stack", page, &attrs) != 0)
        return (void *) 1;
    return NULL;
}

static int
run_s1(void)
{
    ULONG attrs = 0;
    int result = 0;

    MARK("S1", "start (GetMemoryAttrs-only probes)");

    /* Non-stack pages first. */
    void *priv = AllocVecTags(PAGE_SIZE,
                              AVT_Type,      MEMF_PRIVATE,
                              AVT_Alignment, PAGE_SIZE,
                              TAG_DONE);
    if (priv != NULL) {
        if (probe_attrs("S1", "MEMF_PRIVATE", priv, &attrs) != 0)
            result = 1;
        FreeVec(priv);
    } else {
        MARK("S1", "AllocVecTags(MEMF_PRIVATE) FAILED");
        result = 1;
    }

    void *shared = AllocVecTags(PAGE_SIZE,
                                AVT_Type,      MEMF_SHARED,
                                AVT_Alignment, PAGE_SIZE,
                                TAG_DONE);
    if (shared != NULL) {
        if (probe_attrs("S1", "MEMF_SHARED", shared, &attrs) != 0)
            result = 1;
        FreeVec(shared);
    } else {
        MARK("S1", "AllocVecTags(MEMF_SHARED) FAILED");
        result = 1;
    }

    /* Then the stack pages. */
    if (probe_attrs("S1", "main-task-stack", main_task_stack_low_page(),
                    &attrs) != 0)
        result = 1;

    pthread_t t;
    void *tret = NULL;
    if (pthread_create(&t, NULL, s1_thread, NULL) == 0) {
        pthread_join(t, &tret);
        if (tret != NULL)
            result = 1;
    } else {
        MARK("S1", "pthread_create FAILED");
        result = 1;
    }

    MARK("S1", "%s", result == 0 ? "PASS" : "FAIL");
    return result;
}

/* ------------------------------------------------------------- S2 / S3 */

struct own_stack_case {
    const char *name;
    int         prot;
    const char *prot_name;
    int         result;
};

static void *
own_stack_thread(void *arg)
{
    struct own_stack_case *c = arg;
    void *page = own_pthread_stack_low_page();

    if (page == NULL) {
        MARK(c->name, "own pthread stack page lookup FAILED");
        c->result = 1;
        return NULL;
    }
    c->result = (protect_restore(c->name, "own-pthread-stack", page,
                                 c->prot, c->prot_name) == 0) ? 0 : 1;
    return NULL;
}

static int
run_own_stack_case(const char *name, int prot, const char *prot_name)
{
    struct own_stack_case c = { name, prot, prot_name, 1 };
    pthread_t t;

    MARK(name, "start (own pthread stack low page, %s)", prot_name);
    if (pthread_create(&t, NULL, own_stack_thread, &c) != 0) {
        MARK(name, "pthread_create FAILED");
        return 1;
    }
    pthread_join(t, NULL);
    MARK(name, "%s", c.result == 0 ? "PASS" : "FAIL");
    return c.result;
}

/* ------------------------------------------------------------------ S4 */

static int
run_s4(void)
{
    int result;

    MARK("S4", "start (main CLI task stack low page)");
    result = (protect_restore("S4", "main-task-stack",
                              main_task_stack_low_page(),
                              PROT_READ, "PROT_READ") == 0) ? 0 : 1;
    MARK("S4", "%s", result == 0 ? "PASS" : "FAIL");
    return result;
}

/* ------------------------------------------------------------------ S5 */

static sem_t s5_sem;
static volatile int s5_parked = 0;

static void *
s5_sibling(void *arg)
{
    (void) arg;
    s5_parked = 1;
    sem_wait(&s5_sem); /* park until main is done poking our stack */
    return NULL;
}

static int
run_s5(void)
{
    pthread_t t;
    int result = 1;

    MARK("S5", "start (sibling pthread's stack page, from main)");

    if (sem_init(&s5_sem, 0, 0) != 0) {
        MARK("S5", "sem_init FAILED");
        return 1;
    }
    if (pthread_create(&t, NULL, s5_sibling, NULL) != 0) {
        MARK("S5", "pthread_create FAILED");
        return 1;
    }
    while (!s5_parked)
        usleep(10000);
    usleep(100000); /* let it actually enter sem_wait */

    void *page = thread_stack_low_page(t);
    if (page == NULL) {
        MARK("S5", "sibling stack page lookup FAILED");
    } else {
        result = (protect_restore("S5", "sibling-pthread-stack", page,
                                  PROT_READ, "PROT_READ") == 0) ? 0 : 1;
    }

    sem_post(&s5_sem);
    pthread_join(t, NULL);
    sem_destroy(&s5_sem);

    MARK("S5", "%s", result == 0 ? "PASS" : "FAIL");
    return result;
}

/* ------------------------------------------------------------------ S7 */
/*
 * S7 -- THE DISCRIMINATOR for gate 2f / R-3.  SAFE: no stack page is
 * touched, only an mmap()'d page of our own.
 *
 * It reads the MMU attributes back at each step of a PROT_NONE round trip,
 * which is the one measurement that separates the two live explanations of
 * "restore after PROT_NONE returns -1":
 *
 *   H1  clib4's own probe-then-commit guard rejects the restore.
 *       mprotect maps PROT_NONE to MEMATTRF_SUPER_RW, and
 *       MEMATTRF_SUPER_RW == (0L<<6) == 0 (SDK exec/memory.h:209), so a
 *       PROT_NONE page with default cache policy reads back as attrs == 0
 *       -- which the old guard treated as "unmapped" and refused.
 *       => PREDICTS  A1 == 0x00000000.
 *
 *   H2  the OS4 MMU refuses the transition out of no-access, i.e.
 *       SetMemoryAttrs itself will not take a page from SUPER_RW back to
 *       SUPER_RW_USER_RW.
 *       => PREDICTS  A1 != 0 (the page still describes itself), and, on a
 *          clib4 whose guard has been fixed, A2 != READ_WRITE after a
 *          restore that reported rc == 0.
 *
 * The two predictions are mutually exclusive on A1, so one run decides it.
 *
 * Note this case uses an mmap() page deliberately.  If the failure
 * reproduces here, R-3 is NOT a stack-page defect and has nothing to do
 * with issue #431 or with guard pages -- it is address-class independent,
 * and the whole "HotSpot guard page" framing of the risk is wrong.  If it
 * does NOT reproduce here but S3 still fails, the opposite holds and the
 * stack VA is essential.  Either answer is worth the run.
 *
 * Expected attribute values for reference (SDK exec/memory.h:209-213):
 *   MEMATTRF_SUPER_RW         = 0x000  (PROT_NONE:  user no access)
 *   MEMATTRF_SUPER_RW_USER_RW = 0x080  (PROT_READ|PROT_WRITE)
 *   MEMATTRF_SUPER_RO_USER_RO = 0x0C0  (PROT_READ)
 *   MEMATTRF_NOT_MAPPED       = 0x400  (returned for unmapped memory)
 */
static int
run_s7(void)
{
    ULONG a0 = 0, a1 = 0, a2 = 0;
    int rc_none, rc_restore;
    int result = 0;

    MARK("S7", "start (PROT_NONE round trip on an mmap page, "
               "with GetMemoryAttrs readback at each step)");

    void *m = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        MARK("S7", "mmap FAILED");
        return 1;
    }

    if (probe_attrs("S7", "mmap-page/initial-RW", m, &a0) != 0)
        result = 1;

    rc_none = mprotect_reported("S7", "mmap-page", m, PROT_NONE,
                                "PROT_NONE", "apply");

    /* THE MEASUREMENT.  Read the attributes back while the page is under
     * PROT_NONE, without going through mprotect (whose guard is the thing
     * under test). */
    if (probe_attrs("S7", "mmap-page/under-PROT_NONE", m, &a1) != 0)
        result = 1;

    rc_restore = mprotect_reported("S7", "mmap-page", m,
                                   PROT_READ | PROT_WRITE,
                                   "PROT_READ|PROT_WRITE", "restore");

    if (probe_attrs("S7", "mmap-page/after-restore", m, &a2) != 0)
        result = 1;

    MARK("S7", "SUMMARY attrs: initial=0x%08lx under-PROT_NONE=0x%08lx "
               "after-restore=0x%08lx | rc(PROT_NONE)=%d rc(restore)=%d",
         (unsigned long) a0, (unsigned long) a1, (unsigned long) a2,
         rc_none, rc_restore);
    MARK("S7", "VERDICT: under-PROT_NONE attrs %s -- %s",
         a1 == 0 ? "== 0" : "!= 0",
         a1 == 0 ? "H1 (clib4's attrs==0 sentinel misreads a valid page)"
                 : "H2 (not the sentinel; look at SetMemoryAttrs itself)");

    munmap(m, PAGE_SIZE);

    if (rc_none != 0 || rc_restore != 0)
        result = 1;

    MARK("S7", "%s", result == 0 ? "PASS" : "FAIL");
    return result;
}

/* ------------------------------------------------------------------ S8 */
/*
 * S8 -- can GetMemoryAttrs tell "unmapped" from "mapped but PROT_NONE"?
 *
 * DANGER: this is the one case here that deliberately probes addresses we
 * do not own.  It may DSI, and a DSI inside SuperState can suspend the task
 * silently rather than trapping.  RUN IT LAST, ALONE, AND EXPECT TO NEED A
 * REBOOT.  A marker is printed before every single probe so the serial log
 * attributes the death to one exact address.
 *
 * Why it is worth the risk: clib4's mprotect guard must decide, from a
 * GetMemoryAttrs result alone, whether a page is mapped.  Since PROT_NONE
 * pages read back as 0 (see S7), the guard can only work if genuinely
 * unmapped VAs read back as something else -- the header promises
 * MEMATTRF_NOT_MAPPED (0x400).
 *
 *   attrs == 0x400 (or NOT_MAPPED set) on the unmapped candidates
 *       => the header is right, the guard is sound, done.
 *   attrs == 0 on an unmapped candidate
 *       => 0 is AMBIGUOUS between unmapped and PROT_NONE.  The guard cannot
 *          be made both safe and correct with GetMemoryAttrs alone, and
 *          clib4 must instead decide mapped-ness from __mmap_records plus
 *          the caller's own stack bounds.  This is the more important and
 *          more expensive outcome.
 *   a DSI / silent suspend inside the probe
 *       => GetMemoryAttrs FAULTS on unmapped VAs, which is issue #431's top
 *          hypothesis and review finding A2.  The probe-then-commit design
 *          is then unsalvageable as written: it relocates the fault into
 *          SuperState instead of preventing it.
 *
 * All three answers change what clib4 should do.  There is no outcome here
 * that is merely confirmatory.
 */
static int
run_s8(void)
{
    static const struct { const char *what; uintptr_t va; } cand[] = {
        /* Ordered least to most likely to be genuinely unmapped, so the log
         * shows how far the walk got before anything went wrong. */
        { "low-memory-page-1",  0x00001000UL },
        { "mid-hole-0x50000000", 0x50000000UL },
        { "high-hole-0x7FF00000", 0x7FF00000UL },
    };
    ULONG attrs;
    size_t i;
    int result = 0;

    MARK("S8", "start -- DANGEROUS: probing addresses we do not own. "
               "A silent stop after any 'before' line below means "
               "GetMemoryAttrs FAULTED on that address.");

    for (i = 0; i < sizeof(cand) / sizeof(cand[0]); i++) {
        attrs = 0xDEADBEEFUL;
        if (probe_attrs("S8", cand[i].what, (void *) cand[i].va, &attrs) != 0) {
            result = 1;
            continue;
        }
        MARK("S8", "%s (%p): attrs=0x%08lx -> %s", cand[i].what,
             (void *) cand[i].va, (unsigned long) attrs,
             (attrs & 0x400UL) ? "MEMATTRF_NOT_MAPPED set (header is right)"
             : attrs == 0 ? "ZERO -- AMBIGUOUS with a PROT_NONE page"
                          : "mapped, some other attributes");
    }

    MARK("S8", "survived all probes (no fault)");
    MARK("S8", "%s", result == 0 ? "PASS" : "FAIL");
    return result;
}

/* ---------------------------------------------------------------- main */

int
main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s S1|S2|S3|S4|S5|S6|S7|S8\n", argv[0]);
        printf("recommended order (safe cases first): S6 S7 S1 S2 S3 S4 S5\n");
        printf("S8 is DANGEROUS (probes unowned addresses) -- run it LAST\n");
        printf("run one case per invocation so a crash cannot mask the rest\n");
        return 1;
    }

    if (strcmp(argv[1], "S1") == 0)
        return run_s1();
    if (strcmp(argv[1], "S2") == 0)
        return run_own_stack_case("S2", PROT_READ, "PROT_READ");
    if (strcmp(argv[1], "S3") == 0)
        return run_own_stack_case("S3", PROT_NONE, "PROT_NONE");
    if (strcmp(argv[1], "S4") == 0)
        return run_s4();
    if (strcmp(argv[1], "S5") == 0)
        return run_s5();
    if (strcmp(argv[1], "S6") == 0)
        return run_s6();
    if (strcmp(argv[1], "S7") == 0)
        return run_s7();
    if (strcmp(argv[1], "S8") == 0)
        return run_s8();

    printf("unknown case '%s'\n", argv[1]);
    return 1;
}
