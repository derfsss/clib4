/*
 * mutex_cancel.c — verify that pthread_mutex_lock() is wakeable by
 * pthread_cancel() (the MutexAttemptWithSignal loop in
 * library/pthread/pthread_mutex_lock.c).
 *
 * Background: exec.library's MutexObtain() waits in the kernel with no
 * signal mask, so the signal-based cancel mechanism could never wake a
 * thread parked in pthread_mutex_lock(); __pthread_exit_func's join loop
 * then wedged forever at process exit (there is no SIGKILL on AmigaOS).
 *
 * Cases (argv[1] selects; no argument runs T1 then T3):
 *   T1  A locks M; B blocks in pthread_mutex_lock(M); main cancels B and
 *       joins it — the join must complete within 2 s, B's cleanup handler
 *       must have run, and M must still be owned by A and unlockable.
 *   T2  main locks M, spawns 4 threads that all block on M, then calls
 *       exit(0).  The process must terminate (observe from the shell —
 *       no leftover "pthread id #N" processes in Status).  Run explicitly.
 *   T3  regression: B waits in pthread_cond_wait(C, M); main cancels B —
 *       the cancellation cleanup's internal mutex relock must complete
 *       (proves no pthread_testcancel recursion in cleanup handlers).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

static pthread_mutex_t M = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  C = PTHREAD_COND_INITIALIZER;

static volatile int cleanup_ran = 0;
static volatile int b_entered = 0;

static double
elapsed_since(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double) (now.tv_sec - start->tv_sec) +
           (double) (now.tv_nsec - start->tv_nsec) / 1e9;
}

/* ------------------------------------------------------------------ T1 */

static void
t1_cleanup(void *arg)
{
    (void) arg;
    cleanup_ran = 1;
}

static void *
t1_blocker(void *arg)
{
    (void) arg;
    pthread_cleanup_push(t1_cleanup, NULL);
    b_entered = 1;
    /* A holds M: this blocks until cancellation wakes us. */
    pthread_mutex_lock(&M);
    /* Only reached if the lock is ever granted (it must not be). */
    pthread_mutex_unlock(&M);
    pthread_cleanup_pop(0);
    return NULL;
}

static int
run_t1(void)
{
    pthread_t b;
    struct timespec start;
    void *ret = NULL;
    double secs;

    printf("T1: start\n");

    cleanup_ran = 0;
    b_entered = 0;

    /* main plays "A": grab M so B must block. */
    pthread_mutex_lock(&M);

    if (pthread_create(&b, NULL, t1_blocker, NULL) != 0) {
        printf("T1 FAIL: pthread_create\n");
        return 1;
    }

    /* Give B time to park inside pthread_mutex_lock. */
    while (!b_entered)
        usleep(10000);
    usleep(200000);

    clock_gettime(CLOCK_MONOTONIC, &start);
    printf("T1: canceling blocked thread\n");
    pthread_cancel(b);
    pthread_join(b, &ret);
    secs = elapsed_since(&start);

    printf("T1: join returned after %.3f s (ret=%s, cleanup_ran=%d)\n",
           secs, (ret == PTHREAD_CANCELED) ? "PTHREAD_CANCELED" : "other",
           cleanup_ran);

    if (secs > 2.0) {
        printf("T1 FAIL: cancel+join took %.3f s (> 2 s) — "
               "mutex wait not cancelable\n", secs);
        return 1;
    }
    if (ret != PTHREAD_CANCELED) {
        printf("T1 FAIL: thread was not canceled\n");
        return 1;
    }
    if (!cleanup_ran) {
        printf("T1 FAIL: cleanup handler did not run\n");
        return 1;
    }

    /* M must still be ours and unlockable. */
    if (pthread_mutex_unlock(&M) != 0) {
        printf("T1 FAIL: mutex unlock after cancel failed\n");
        return 1;
    }
    /* And still usable. */
    if (pthread_mutex_lock(&M) != 0 || pthread_mutex_unlock(&M) != 0) {
        printf("T1 FAIL: mutex unusable after cancel\n");
        return 1;
    }

    printf("T1 PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ T2 */

#define T2_THREADS 4

static void *
t2_blocker(void *arg)
{
    (void) arg;
    pthread_mutex_lock(&M);
    pthread_mutex_unlock(&M);
    return NULL;
}

static int
run_t2(void)
{
    pthread_t t[T2_THREADS];
    int i;

    printf("T2: start — locking M and spawning %d blocked threads\n",
           T2_THREADS);

    pthread_mutex_lock(&M);

    for (i = 0; i < T2_THREADS; i++) {
        if (pthread_create(&t[i], NULL, t2_blocker, NULL) != 0) {
            printf("T2 FAIL: pthread_create %d\n", i);
            return 1;
        }
    }

    /* Let them all park inside pthread_mutex_lock. */
    sleep(1);

    printf("T2: calling exit(0) with %d threads blocked on M — "
           "the process must terminate now.\n", T2_THREADS);
    printf("T2: (verify from the shell: prompt returns, and Status shows "
           "no leftover pthread processes)\n");
    fflush(stdout);
    exit(0);
    return 0; /* not reached */
}

/* ------------------------------------------------------------------ T3 */

static void
t3_cleanup(void *arg)
{
    (void) arg;
    /* Runs during cancellation.  Relock/unlock the mutex from inside a
     * cleanup handler: on a TERMINATING thread this must degrade to a
     * plain (non-cancelable) wait and complete — no testcancel recursion. */
    pthread_mutex_lock(&M);
    cleanup_ran = 1;
    pthread_mutex_unlock(&M);
}

static void *
t3_waiter(void *arg)
{
    (void) arg;
    pthread_mutex_lock(&M);
    pthread_cleanup_push(t3_cleanup, NULL);
    b_entered = 1;
    while (1)
        pthread_cond_wait(&C, &M); /* cancellation point */
    pthread_cleanup_pop(0);
    pthread_mutex_unlock(&M);
    return NULL;
}

static int
run_t3(void)
{
    pthread_t b;
    struct timespec start;
    void *ret = NULL;
    double secs;

    printf("T3: start\n");

    cleanup_ran = 0;
    b_entered = 0;

    if (pthread_create(&b, NULL, t3_waiter, NULL) != 0) {
        printf("T3 FAIL: pthread_create\n");
        return 1;
    }

    /* Let B park inside pthread_cond_wait. */
    while (!b_entered)
        usleep(10000);
    usleep(200000);

    clock_gettime(CLOCK_MONOTONIC, &start);
    printf("T3: canceling cond-waiting thread\n");
    pthread_cancel(b);
    pthread_join(b, &ret);
    secs = elapsed_since(&start);

    printf("T3: join returned after %.3f s (cleanup_ran=%d)\n",
           secs, cleanup_ran);

    if (secs > 2.0) {
        printf("T3 FAIL: cancel+join took %.3f s (> 2 s)\n", secs);
        return 1;
    }
    if (!cleanup_ran) {
        printf("T3 FAIL: cleanup handler's mutex relock never completed\n");
        return 1;
    }

    /* M must be free again. */
    if (pthread_mutex_lock(&M) != 0 || pthread_mutex_unlock(&M) != 0) {
        printf("T3 FAIL: mutex unusable after cancel\n");
        return 1;
    }

    printf("T3 PASS\n");
    return 0;
}

/* ---------------------------------------------------------------- main */

int
main(int argc, char **argv)
{
    if (argc > 1) {
        if (strcmp(argv[1], "T1") == 0)
            return run_t1();
        if (strcmp(argv[1], "T2") == 0)
            return run_t2();
        if (strcmp(argv[1], "T3") == 0)
            return run_t3();
        printf("usage: %s [T1|T2|T3]\n", argv[0]);
        return 1;
    }

    /* Default: the in-process cases.  T2 ends with exit(0) and must be
     * observed from the shell, so it only runs when asked for. */
    if (run_t1() != 0)
        return 1;
    if (run_t3() != 0)
        return 1;
    printf("ALL PASS (run \"%s T2\" separately to check the exit path)\n",
           argv[0]);
    return 0;
}
