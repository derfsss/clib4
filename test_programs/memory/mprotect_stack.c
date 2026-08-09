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
 *
 * Safety: only ever the LOWEST page of a stack is touched, far below the
 * live SP; it is restored immediately; nothing recurses between protect
 * and restore.
 */

#define __USE_INLINE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* mprotect + restore with markers around each call.  restore_prot is
 * applied whether or not the first call succeeded (best effort).         */
static int
protect_restore(const char *case_name, const char *what, void *addr,
                int prot, const char *prot_name)
{
    int rc1, rc2;

    MARK(case_name, "before mprotect(%p, %lu, %s) [%s]",
         addr, PAGE_SIZE, prot_name, what);
    rc1 = mprotect(addr, PAGE_SIZE, prot);
    MARK(case_name, "after mprotect(%p, %s) [%s] -> rc=%d", addr, prot_name,
         what, rc1);

    MARK(case_name, "before restore mprotect(%p, %lu, PROT_READ|PROT_WRITE) [%s]",
         addr, PAGE_SIZE, what);
    rc2 = mprotect(addr, PAGE_SIZE, PROT_READ | PROT_WRITE);
    MARK(case_name, "after restore mprotect(%p) [%s] -> rc=%d", addr, what, rc2);

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

/* ---------------------------------------------------------------- main */

int
main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s S1|S2|S3|S4|S5|S6\n", argv[0]);
        printf("recommended order (safe cases first): S6 S1 S2 S3 S4 S5\n");
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

    printf("unknown case '%s'\n", argv[1]);
    return 1;
}
