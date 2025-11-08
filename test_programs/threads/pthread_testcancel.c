/*
 * pthread_testcancel_example.c
 *
 * Demonstrates pthread_cancel, pthread_testcancel, deferred vs asynchronous cancellation,
 * cleanup handlers, and checking join return values (PTHREAD_CANCELED).
 *
 * Compile:
 *   gcc -Wall -Wextra -pthread -o pthread_testcancel_example pthread_testcancel_example.c
 *
 * Run:
 *   ./pthread_testcancel_example
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

/* Cleanup handler used by both threads */
static void cleanup_handler(void *arg) {
    char *name = (char *)arg;
    printf("[cleanup] Running cleanup for %s\n", name);
    /* If there were allocated resources, free them here. */
}

/* Worker that demonstrates deferred cancellation.
 * It periodically does work and explicitly calls pthread_testcancel()
 * so it is cancelable at that point.
 */
void *worker_deferred(void *arg) {
    const char *name = "deferred-thread";

    /* Register cleanup handler (must be paired with pthread_cleanup_pop) */
    pthread_cleanup_push(cleanup_handler, (void *)name);

    printf("[%s] started (deferred cancellation -- default)\n", name);

    for (int i = 0; i < 20; ++i) {
        /* Simulate some work */
        printf("[%s] iteration %d\n", name, i);
        /* Sleep for a short time - sleep is a cancellation point too */
        sleep(1);

        /* Explicit cancellation point */
        pthread_testcancel();

        /* Continue doing work... */
    }

    printf("[%s] finished normally\n", name);

    /* Remove cleanup handler and do NOT execute it (0), because not canceled */
    pthread_cleanup_pop(0);
    return (void *)0;
}

/* Worker that demonstrates asynchronous cancellation.
 * It sets cancellation type to PTHREAD_CANCEL_ASYNCHRONOUS.
 * This means the thread may be canceled at any time — cleanup handlers must clean resources.
 */
void *worker_async(void *arg) {
    const char *name = "async-thread";
    int oldtype;

    /* Set cancellation to asynchronous */
    if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype) != 0) {
        perror("pthread_setcanceltype");
        /* fallback: keep going as deferred */
    }

    pthread_cleanup_push(cleanup_handler, (void *)name);

    printf("[%s] started (asynchronous cancellation)\n", name);

    /* Simulate a loop that performs many operations; cancellation can occur at nearly any moment */
    for (int i = 0; i < 1000; ++i) {
        printf("[%s] iteration %d\n", name, i);

        /* Do a short busy wait to simulate work (no cancellation point here necessarily) */
        for (volatile int z = 0; z < 10000000; ++z) {
            /* busy */
        }

        /* Optionally you could call pthread_testcancel(); not required for async type */
    }

    printf("[%s] finished normally\n", name);

    pthread_cleanup_pop(0);
    return (void *)0;
}

int main(void) {
    pthread_t t_deferred, t_async;
    void *res;

    printf("Main: create threads\n");

    if (pthread_create(&t_deferred, NULL, worker_deferred, NULL) != 0) {
        perror("pthread_create deferred");
        return EXIT_FAILURE;
    }

    if (pthread_create(&t_async, NULL, worker_async, NULL) != 0) {
        perror("pthread_create async");
        /* cancel and join the other thread before exit */
        pthread_cancel(t_deferred);
        pthread_join(t_deferred, NULL);
        return EXIT_FAILURE;
    }

    /* Give threads some time to run */
    sleep(3);

    printf("Main: sending cancellation to deferred thread\n");
    if (pthread_cancel(t_deferred) != 0) {
        perror("pthread_cancel deferred");
    }

    /* Give a bit more time, then cancel the async thread */
    sleep(2);
    printf("Main: sending cancellation to async thread\n");
    if (pthread_cancel(t_async) != 0) {
        perror("pthread_cancel async");
    }

    /* Join deferred thread and check result */
    if (pthread_join(t_deferred, &res) != 0) {
        perror("pthread_join deferred");
    } else {
        if (res == PTHREAD_CANCELED) {
            printf("Main: deferred thread was canceled (res == PTHREAD_CANCELED)\n");
        } else {
            printf("Main: deferred thread returned normally (res = %p)\n", res);
        }
    }

    /* Join async thread and check result */
    if (pthread_join(t_async, &res) != 0) {
        perror("pthread_join async");
    } else {
        if (res == PTHREAD_CANCELED) {
            printf("Main: async thread was canceled (res == PTHREAD_CANCELED)\n");
        } else {
            printf("Main: async thread returned normally (res = %p)\n", res);
        }
    }

    printf("Main: exiting\n");
    return EXIT_SUCCESS;
}
