/*
  $Id: pthread_mutex_lock.c,v 1.00 2022-07-18 12:09:49 clib4devs Exp $

  Copyright (C) 2014 Szilard Biro
  Copyright (C) 2018 Harry Sintonen
  Copyright (C) 2019 Stefan "Bebbo" Franke - AmigaOS 3 port

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

#ifndef _TIME_HEADERS_H
#include "time_headers.h"
#endif /* _TIME_HEADERS_H */

#ifndef _STDIO_HEADERS_H
#include "stdio_headers.h"
#endif /* _STDIO_HEADERS_H */

#ifndef _UNISTD_HEADERS_H
#include "unistd_headers.h"
#endif /* _UNISTD_HEADERS_H */

#include "common.h"
#include "pthread.h"

int
pthread_mutex_lock(pthread_mutex_t *mutex) {
    ENTER();
    SHOWPOINTER(mutex);

    if (!mutex) {
        LEAVE();
        return EINVAL;
    }

    if (mutex->mutex == NULL) {
        SHOWMSG("mutex was not initalized. Initialize it");
        int ret = _pthread_mutex_init(mutex, NULL, TRUE);
        if (ret != 0) {
            SHOWMSG("Cannot initialize mutex");
            LEAVE();
            return EINVAL;
        }
    }

	// ERRORCHECK mutexes return EDEADLK instead of deadlocking
	if (mutex->kind == PTHREAD_MUTEX_ERRORCHECK && MutexIsMine(mutex)) {
		LEAVE();
		return EDEADLK;
	}

    /*
     * Blocking tail.  Exec's MutexObtain() waits inside the kernel with no
     * signal mask, so a thread parked in it can never be woken by the
     * signal-based pthread_cancel() mechanism — __pthread_exit_func's join
     * loop then wedges forever on process exit (there is no SIGKILL on
     * AmigaOS).  To keep cancellation deliverable we wait with
     * MutexAttemptWithSignal() (the same primitive pthread_mutex_timedlock
     * relies on), including the thread's dedicated cancel signal, and run
     * pthread_testcancel() whenever it fires.
     *
     * NOTE: POSIX says pthread_mutex_lock is NOT a cancellation point; this
     * is a deliberate deviation (deferred cancel only, honoring
     * pthread_setcancelstate).  Threads already TERMINATING/DESTRUCT (i.e.
     * running cancellation-cleanup handlers, which routinely relock
     * mutexes) fall back to the plain uninterruptible MutexObtain(), and
     * pthread_exit()'s re-entry check guards against testcancel recursion.
     */
    ThreadInfo *inf = GetCurrentThreadInfo();
    uint32 cancel_mask = 0;

    if (inf != NULL &&
        inf->cancelstate == PTHREAD_CANCEL_ENABLE &&
        inf->status != THREAD_STATE_TERMINATING &&
        inf->status != THREAD_STATE_DESTRUCT)
        cancel_mask = inf->cancel_signal_mask;

    if (cancel_mask == 0) {
        SHOWMSG("MutexObtain");
        MutexObtain(mutex->mutex);
    } else {
        /* Hardening: if a cancellation was flagged but its wake-up signal
         * was already consumed before we got here (e.g. by an unrelated
         * Wait/sigtimedwait), the loop below would park uncancellably —
         * test once before the first wait to close that window. */
        pthread_testcancel();
        SHOWMSG("MutexAttemptWithSignal");
        for (;;) {
            uint32 sigs = MutexAttemptWithSignal(mutex->mutex, cancel_mask);
            if (!(sigs & cancel_mask))
                break;                          /* mutex acquired */
            /* Woken by the cancel signal.  If a real cancellation is
             * pending this exits the thread (deferred-cancel style);
             * otherwise it clears the signal and we re-wait. */
            pthread_testcancel();
        }
    }
    mutex->owner = FindTask(NULL);
    SHOWMSG("Done");

    RETURN(0);
    return 0;
}
