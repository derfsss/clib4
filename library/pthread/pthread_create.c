/*
  $Id: pthread_create.c,v 1.00 2022-07-18 12:09:49 clib4devs Exp $

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

extern struct DOSIFace *_IDOS;

/*
 * pthread_create() has five distinct failure paths and POSIX gives it exactly
 * one error code to report them with, EAGAIN.  Worse, the code is the RETURN
 * VALUE, not errno, and the most important caller on this platform throws it
 * away: OpenJDK's CallJavaMainInNewThread (java_md.c) tests
 * `pthread_create(...) == 0' and on failure silently runs JavaMain on the
 * primary process instead, with the comment "just give it a try..".  The VM
 * then behaves subtly differently for the rest of its life and nothing
 * anywhere records why.
 *
 * So say it on the serial log, unconditionally.  This is the same channel the
 * DOS ELF loader uses for "[DOS ELF_LS] ERROR: ... Elf32_Error=10", it is
 * already captured on every guest run, and it costs nothing when no thread
 * creation ever fails.  Precedent for unconditional DebugPrintF from library
 * code: library/stdio/fread.c:248, library/wmem/wmem_core.c:241.
 *
 * This deliberately does NOT change the returned code -- EAGAIN is
 * POSIX-conformant for every one of these paths and callers may rely on it.
 * Making the failure loud and making it a different errno are separate
 * decisions; only the first is safe to take unilaterally.
 */
#define STR_(x) #x
#define STR(x)  STR_(x)
#define PTHREAD_CREATE_FAILED(reason) \
    DebugPrintF("[clib4 pthread_create] FAILED (returning EAGAIN): %s\n", (reason))

/*
 * How the child process gets its three DOS standard handles.
 *
 * The dup exists to TRANSFER OWNERSHIP: NP_CloseInput/Output/Error TRUE tells
 * DOS to close the child's handles when it exits, and that must not close the
 * parent's.  So the rule is simply: dup transfers ownership; when we cannot
 * dup, we borrow instead of owning.  Three cases:
 *
 *   src == ZERO       The parent has no such stream.  TAG_IGNORE the handle
 *                     tag (but NEVER the NP_Close* one -- see below) and let
 *                     the child have none either.  Per
 *                     dos.doc, ErrorOutput() "will generally return ZERO
 *                     unless someone specifically opens an error output
 *                     stream" and DupFileHandle(ZERO) "always returns ZERO",
 *                     so this is the DOCUMENTED GENERAL CASE, not an error.
 *                     clib4's own stdio already treats it as such:
 *                     library/stdio/file_init.c:202 guards with
 *                     `if (default_file != BZERO)' and initialises stderr
 *                     regardless.  Refusing to create a thread for a process
 *                     that merely lacks an error stream was the bug.
 *
 *   dup OK            Pass the dup, NP_Close* TRUE.  Unchanged behaviour.
 *
 *   dup FAILED on a   The handle is real and DupFileHandle genuinely refused
 *   non-ZERO handle   it -- in practice a pipe, IoErr()==ERROR_OBJECT_IN_USE
 *                     (202), which is what every capture harness produces for
 *                     stdout.  Pass the ORIGINAL handle with NP_Close* FALSE:
 *                     the child borrows the parent's stream and DOS will not
 *                     close it on the child's exit.
 *
 * Why borrowing is the right answer for that third case, rather than
 * substituting ZERO or NIL: -- both of which would have made the symptom go
 * away just as well, and silently:
 *
 *   1. It is what POSIX already promises.  Threads share the process's
 *      streams; they do not get private copies.
 *   2. clib4 itself already borrows these very handles.  file_init.c captures
 *      Input()/Output()/ErrorOutput() ONCE into the per-process __clib4 fd
 *      table and flags them FDF_NO_CLOSE_BPTR -- clib4 has never owned them.
 *      A pthread's printf() resolves through that shared table, NOT through
 *      the child Process's pr_COS, so the child's DOS handles are near-
 *      vestigial for clib4 I/O.  Borrowing keeps the DOS-level view
 *      consistent with the stdio-level view that already exists.
 *   3. ZERO or NIL: would discard a thread's DOS-level output with nothing
 *      recording that it had happened -- a plausible wrong answer, which is
 *      the one outcome this library must not produce.
 *
 * The honest risk, stated rather than hidden: two DOS Processes then hold one
 * FileHandle, and AmigaOS FileHandles are not reentrant, so concurrent writes
 * can interleave.  That hazard is NOT new -- the shared __clib4 fd table has
 * exactly the same property today -- and POSIX makes interleaving on a shared
 * stream the caller's problem.  The second risk is lifetime: a borrowed handle
 * must outlive the child.  __pthread_exit_func cancels and joins every live
 * thread before the process tears down, which bounds it.  Neither risk is
 * silent: every borrow is reported below.
 */
struct handle_pass {
    ULONG tag;        /* NP_Input / NP_Output / NP_Error, or TAG_IGNORE   */
    BPTR  fh;
    LONG  close;      /* TRUE only when the CHILD OWNS the handle         */
};

/*
 * ⛔ The NP_Close* tag is ALWAYS passed explicitly by the caller and is never
 * TAG_IGNOREd, because the DOS defaults are the dangerous way round:
 *
 *     dos.doc:3383  NP_CloseInput  ... Defaults to TRUE.
 *     dos.doc:3392  NP_CloseOutput ... Defaults to TRUE.
 *
 * Omitting the tag therefore tells DOS to CLOSE the child's input/output on
 * exit -- and when NP_Input/NP_Output were also omitted, that stream is
 * whatever DOS defaulted the child to, which may be the parent's.  A child
 * thread exiting would then close the process's own stdout.  So this struct
 * carries only the boolean; the tag itself is spelled out at the call site
 * where it cannot be lost.  (NP_Error is the exception that proves it:
 * dos.doc:3396 defaults it to a ZERO stream, which is why omitting THAT one
 * is safe -- but it is not omitted either, for symmetry.)
 */
static void
resolve_handle(struct handle_pass *hp, BPTR *owned, BPTR src,
               ULONG tag, const char *what) {
    *owned = BZERO;

    if (src == BZERO) {
        /* Documented general case; give the child no such stream, and make
         * certain it does not close a defaulted one on the way out. */
        hp->tag = TAG_IGNORE;  hp->fh = BZERO;  hp->close = FALSE;
        return;
    }

    *owned = DupFileHandle(src);
    if (*owned != BZERO) {
        hp->tag = tag;  hp->fh = *owned;  hp->close = TRUE;
        return;
    }

    /* Real handle, refused dup (pipes give ERROR_OBJECT_IN_USE == 202).
     * Borrow it: the child uses the parent's stream and must not close it. */
    DebugPrintF("[clib4 pthread_create] DupFileHandle(%s) failed, IoErr=%ld; "
                "child will BORROW the parent's handle (not closed on exit)\n",
                what, (long) IoErr());
    hp->tag = tag;  hp->fh = src;  hp->close = FALSE;
}

static APTR
hook_function(struct Hook *hook, APTR userdata, struct Process *process) {
    uint32 pid = (uint32) userdata;
    (void) (hook);

    if (process->pr_ProcessID == pid) {
        return process;
    }

    return 0;
}

// This is duplicate of killitimer() present in clib4 but is needed since it isn't exposed into interface
static void killitimer_by_thread(uint32 threadID) {
    struct _clib4 *__clib4 = __CLIB4;
    struct TimerNode *node, *next;
    
    /* Scan the timer list for timers belonging to the specified thread */
    for (node = (struct TimerNode *)__clib4->tmr_real_list.mlh_Head;
         (next = (struct TimerNode *)node->tn_Node.mln_Succ) != NULL;
         node = next) {
        
        if (node->tn_ThreadID == threadID) {
            struct Hook h = {{NULL, NULL}, (HOOKFUNC) hook_function, NULL, NULL};
            int32 pid, process;
            
            pid = node->tn_Process->pr_ProcessID;
            /* Scan for process */
            process = ProcessScan(&h, (CONST_APTR) pid, 0);
            D(("Scan for process %ld (%ld) of thread %lu..\n", process, pid, threadID));
            
            while (process > 0) {
                D(("Waiting for process %ld to close..\n", pid));
                /* Send a SIGBREAKF_CTRL_F signal until the timer task return in Wait and can get the signal */
                Signal((struct Task *)node->tn_Process, SIGBREAKF_CTRL_F);
                process = ProcessScan(&h, (CONST_APTR) pid, 0);
                Delay(10);
            }
            
            SHOWMSG("Process closed.. Wait For Child\n");
            WaitForChildExit(pid);
            SHOWMSG("Done\n");
            
            /* Remove from list and free */
            Remove((struct Node *)&node->tn_Node);
            FreeVec(node);
			node = NULL;
        }
    }
}

static uint32
StarterFunc() {
    volatile int keyFound = TRUE;
    struct StackSwapStruct stack;
    volatile BOOL stackSwapped = FALSE;
	DECLARE_UTILITYBASE();

    struct Process *startedTask = (struct Process *) FindTask(NULL);
    ThreadInfo *inf = (ThreadInfo *) startedTask->pr_Task.tc_UserData;
	struct newThreadMessage *newThreadMessage = (struct newThreadMessage *) startedTask->pr_EntryData;

    D(("StarterFunc: thread %s STARTING (task=%p inf=%p)\n", inf->name, startedTask, inf));

    /* Set task pointer immediately so that pthread_self() and
     * GetCurrentThreadInfo() work before the parent's pthread_create
     * has returned and assigned inf->task.  Without this, a fast child
     * can call pthread_self()/pthread_join() while inf->task is still
     * NULL, causing GetThreadId to fail or match a stale slot. */
    inf->task = startedTask;

    // set task TLS register
    set_tls_register(inf);

    struct _clib4 *__clib4 = (struct _clib4 *) startedTask->pr_UID; // GetEntryData();

    // we have to set the priority here to avoid race conditions
    SetTaskPri((struct Task *) startedTask, inf->attr.param.sched_priority);

    // custom stack requires special handling
    if (inf->attr.stackaddr != NULL && inf->attr.stacksize > 0) {
        stack.stk_Lower = inf->attr.stackaddr;
        stack.stk_Upper = (ULONG)((APTR) stack.stk_Lower) + inf->attr.stacksize;
        stack.stk_Pointer = (APTR) stack.stk_Upper;

        StackSwap(&stack);
        stackSwapped = TRUE;
    }

	ReplyMsg(&newThreadMessage->message);

    /* Allocate cancel signal for ALL threads (joinable and detached).
     * Previously this was inside the if(!detached) block, so detached
     * threads could not be cancelled (Signal(task, 0) is a no-op). */
    inf->cancel_signal = AllocSignal(-1);
    if (inf->cancel_signal == -1) {
        inf->cancel_signal_mask = SIGBREAKF_CTRL_C;
        D(("StarterFunc: %s AllocSignal cancel failed, fallback SIGBREAKF_CTRL_C\n", inf->name));
    } else {
        inf->cancel_signal_mask = 1L << inf->cancel_signal;
        D(("StarterFunc: %s allocated cancel signal %d mask 0x%lx\n", inf->name, inf->cancel_signal, (unsigned long)inf->cancel_signal_mask));
    }

    if (!inf->detached) {
        /* Allocate join signal (only needed for joinable threads) */
        inf->join_signal = AllocSignal(-1);
        if (inf->join_signal == -1) {
            inf->join_signal_mask = SIGF_PARENT;
            D(("StarterFunc: %s AllocSignal join failed, fallback SIGF_PARENT\n", inf->name));
        } else {
            inf->join_signal_mask = 1L << inf->join_signal;
            D(("StarterFunc: %s allocated join signal %d mask 0x%lx\n", inf->name, inf->join_signal, (unsigned long)inf->join_signal_mask));
        }
    }

    D(("StarterFunc: thread %s about to call start function\n", inf->name));

    // set a jump point for pthread_exit
    if (!setjmp(inf->jmp)) {
        inf->status = THREAD_STATE_RUNNING;
        D(("StarterFunc: thread %s calling start function NOW\n", inf->name));
        inf->ret = inf->start(inf->arg);
        D(("StarterFunc: thread %s start function RETURNED\n", inf->name));
    }

    /* Don't acquire thread_sem here - let pthread_join register first if it's waiting */

    D(("StarterFunc: thread %s returned from start function\n", inf->name));

    // destroy all non-NULL TLS key values
    // since the destructors can set the keys themselves, we have to do multiple iterations
    for (int j = 0; keyFound && j < PTHREAD_DESTRUCTOR_ITERATIONS; j++) {
        keyFound = FALSE;
        for (int i = 0; i < PTHREAD_KEYS_MAX; i++) {
            void *oldvalue = NULL;
            void (*destructor_func)(void *) = NULL;

            MutexObtain(tls_sem);
            if (inf->tlsvalues[i] && tlskeys[i].used && tlskeys[i].destructor) {
                D(("StarterFunc: thread %s calling destructor for key %d\n", inf->name, i));
                oldvalue = inf->tlsvalues[i];
                destructor_func = tlskeys[i].destructor;
                inf->tlsvalues[i] = NULL;
            }
            MutexRelease(tls_sem);

            /* Call destructor outside of tls_sem to avoid blocking other
             * threads that are exiting and need to run their own destructors */
            if (destructor_func) {
                destructor_func(oldvalue);
                D(("StarterFunc: thread %s destructor for key %d returned\n", inf->name, i));
                keyFound = TRUE;
            }
        }
    }

    /*  If we have timer running tasks for this thread, stop them before exit  */
    if (!IsMinListEmpty(&__clib4->tmr_real_list)) {
        uint32 currentThreadID = (uint32)FindTask(NULL);
        D(("StarterFunc: thread %s has timers, killing them\n", inf->name));
        /* Block SIGALRM signal from raise */
        sigblock(SIGALRM);
        /* Kill itimer for current thread */
        killitimer_by_thread(currentThreadID);
        D(("StarterFunc: thread %s timers killed\n", inf->name));
    }

    /* If we had swapped the stack, restore it */
    if (stackSwapped)
        StackSwap(&stack);


    /* Free our allocated signals in our own task context (before exit).
     * AmigaOS FreeSignal operates on the calling task's signal set, so
     * these must be freed here, not from pthread_join's context.
     * Previously signals were never freed, leaking bits on every thread exit. */

    /* Close per-thread timer device if it was lazily opened */
    if (inf->timerOpen) {
        if (!CheckIO((struct IORequest *)&inf->timerIO))
            AbortIO((struct IORequest *)&inf->timerIO);
        WaitIO((struct IORequest *)&inf->timerIO);
        CloseDevice((struct IORequest *)&inf->timerIO);
        if (inf->timerPort.mp_SigBit != SIGB_TIMER_FALLBACK)
            FreeSignal(inf->timerPort.mp_SigBit);
        inf->timerOpen = FALSE;
    }

    if (inf->cancel_signal != -1 && inf->cancel_signal != SIGBREAKB_CTRL_C) {
        FreeSignal(inf->cancel_signal);
        inf->cancel_signal = -1;
        inf->cancel_signal_mask = 0;
    }
    if (inf->join_signal != -1 && inf->join_signal != SIGB_PARENT) {
        FreeSignal(inf->join_signal);
        inf->join_signal = -1;
        inf->join_signal_mask = 0;
    }
            
    /* NOW acquire thread_sem to atomically set DESTRUCT and search for joiner */
    MutexObtain(thread_sem);

    D(("StarterFunc[%s]: Acquired thread_sem for exit\n", inf->name));

    if (!inf->detached) {
        // tell the parent thread that we are done
        D(("StarterFunc: thread %s not detached, looking for joiner\n", inf->name));
        inf->status = THREAD_STATE_DESTRUCT;

        /* Clear task pointer to prevent ABA false matches.
         * After the process exits, the OS may reuse the Process struct
         * memory for a newly created thread.  If this slot still held
         * the old pointer, GetThreadId / GetCurrentThreadInfo could
         * match the stale entry, returning the wrong ThreadInfo and
         * corrupting the join_list (leading to infinite-loop deadlock).
         * The joiner identifies us by thread_id, not task pointer. */
        inf->task = NULL;

        /* Find who is waiting to join with us */
        ThreadInfo *joiner = NULL;
        struct Node *node;

        D(("StarterFunc: thread %s scanning joiners list for join_id=%ld\n", inf->name, inf->thread_id));

        /* Scan the joiners list */
        for (node = (struct Node *)join_list.mlh_Head;
             node->ln_Succ != NULL;
             node = (struct Node *)node->ln_Succ) {
            joiner = (ThreadInfo *)((char *)node - offsetof(ThreadInfo, join_node));
            D(("StarterFunc: visiting joiner %s (id=%d) waiting for %d\n", joiner->name, joiner->thread_id, joiner->join_thread_id));

            /* Note: Check if thread_id matches what joiner is waiting for */
            if (joiner->join_thread_id == inf->thread_id) {
                D(("StarterFunc: thread %s found joiner (id=%d) waiting for me\n", inf->name, joiner->thread_id));

                /* Set return value in joiner's structure */
                if (inf->status == THREAD_STATE_CANCELED)
                    joiner->join_result = PTHREAD_CANCELED;
                else
                    joiner->join_result = inf->ret;

                /* Signal the joiner */
                if (joiner->join_signal_mask != 0) {
                    D(("StarterFunc: signaling joiner (task=%p) with mask=0x%lx\n", joiner->task, (unsigned long)joiner->join_signal_mask));
                    Signal((struct Task *)joiner->task, joiner->join_signal_mask);
                } else {
                    D(("StarterFunc: WARNING - joiner has no valid join signal!\n"));
                }

                /* POSIX says multiple threads joining same thread is undefined. */
                /* If we continue, we signal all waiters. */
            }
        }

        /* Note: Joinable thread exits here - pthread_join will clean up the ThreadInfo */
        /* We DO NOT remove ourselves from threads array or free resources yet */
    }

    /* Detached threads need self cleanup */
    if (inf->detached) {
        _pthread_clear_threadinfo(inf);
    }
    /* NOTE: Joinable threads do NOT cleanup themselves!
     * pthread_join will do the cleanup after getting the return value.
     * This prevents race where thread clears status before join checks it.
     * Signals are already freed above, before acquiring the lock.
     */

    /* Release lock and exit - process terminates normally */
    D(("StarterFunc[%s]: Releasing thread_sem, exiting\n", inf->name));
    MutexRelease(thread_sem);

    D(("StarterFunc: thread %s exiting\n", inf->name));

	set_tls_register(NULL);

    return RETURN_OK;
}

int
pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start)(void *), void *arg) {
    ThreadInfo *inf;
    char name[NAMELEN] = {0};
    size_t oldlen;
    pthread_t threadnew;
    struct Task *thisTask = FindTask(NULL);
    struct DOSIFace *IDOS = _IDOS;
	/* fileIn/Out/Err are the dups WE created and therefore must clean up on
	 * the error path.  They stay BZERO when the handle was absent or was
	 * borrowed rather than duplicated -- see resolve_handle(). */
	BPTR fileIn  = BZERO;
	BPTR fileOut = BZERO;
	BPTR fileErr = BZERO;
	struct handle_pass hpIn, hpOut, hpErr;
	struct newThreadMessage *newThreadMessage = NULL;
	struct MsgPort *msgPort = NULL;

    if (thread == NULL || start == NULL)
        return EINVAL;

    // grab an empty thread slot and reserve it atomically
    MutexObtain(thread_sem);
    threadnew = GetThreadId(NULL);
    if (threadnew == PTHREAD_THREADS_MAX) {
        MutexRelease(thread_sem);
        PTHREAD_CREATE_FAILED("all " STR(PTHREAD_THREADS_MAX) " thread slots in use");
        return EAGAIN;
    }

    // Reserve the slot before releasing the lock to prevent race conditions
    inf = GetThreadInfo(threadnew);
    _pthread_clear_threadinfo(inf);
    inf->status = THREAD_STATE_RUNNING; // Prevents another GetThreadId(NULL) from returning this slot
    inf->thread_id = threadnew;  /* Save our pthread_t ID */

    D(("pthread_create: slot %d reserved (task %p)\n", threadnew, inf->task));
    inf->start = start;
    inf->arg = arg;
    inf->parent = (struct Process *) thisTask;
    if (attr)
        inf->attr = *attr;
    else
        pthread_attr_init(&inf->attr);
    NewMinList(&inf->cleanup);
    inf->cancelstate = PTHREAD_CANCEL_ENABLE;
    inf->canceltype = PTHREAD_CANCEL_DEFERRED;
    inf->detached = inf->attr.detachstate == PTHREAD_CREATE_DETACHED;
    inf->timerOpen = FALSE;
    
    /* Signals allocated lazily in StarterFunc (thread context).
     *
     * join_signal MUST be initialised here for the same reason cancel_signal
     * is.  _pthread_clear_threadinfo() memset()s the slot to zero, so an
     * uninitialised join_signal reads back as 0 -- which is not the "unset"
     * sentinel (-1) but signal bit 0, SIGB_ABORT.  The out: error path below
     * frees any join_signal != -1, so every pthread_create() that failed
     * before StarterFunc ran was calling FreeSignal(0) on the CALLER's task,
     * releasing a system-reserved signal bit the caller never allocated. */
    inf->cancel_signal = -1;
    inf->cancel_signal_mask = 0;
    inf->join_signal = -1;
    inf->join_signal_mask = 0;

    msgPort = AllocSysObject(ASOT_PORT, NULL);
    if (msgPort == 0) {
        SHOWMSG("Cannot allocate message port\n");
        _pthread_clear_threadinfo(inf); // Release the reserved slot back to IDLE
        MutexRelease(thread_sem);
        PTHREAD_CREATE_FAILED("AllocSysObject(ASOT_PORT) returned 0 (out of memory)");
        return EAGAIN;
    }

	newThreadMessage = AllocSysObjectTags(ASOT_MESSAGE,
		ASOMSG_Size, sizeof(struct newThreadMessage),
		ASOMSG_ReplyPort, msgPort,
		TAG_DONE);
	if (newThreadMessage == NULL) {
		SHOWMSG("Cannot allocate message\n");
        
        FreeSysObject(ASOT_PORT, msgPort);
        msgPort = NULL;
        
        _pthread_clear_threadinfo(inf); // Release the reserved slot back to IDLE
        MutexRelease(thread_sem);
        PTHREAD_CREATE_FAILED("AllocSysObjectTags(ASOT_MESSAGE) returned NULL (out of memory)");
        return EAGAIN;
    }


    /* Check minimum stack size */
    if (inf->attr.stacksize != 0 && inf->attr.stacksize < PTHREAD_STACK_MIN)
        inf->attr.stacksize = PTHREAD_STACK_MIN;

    // Check if we have a guardsize
    if (inf->attr.guardsize > 0)
        inf->attr.stacksize += inf->attr.guardsize;

    // let's trick CreateNewProc into allocating a larger buffer for the name
    snprintf(name, sizeof(name), "pthread id #%d", threadnew);
    oldlen = strlen(name);
    memset(name + oldlen, ' ', sizeof(name) - oldlen - 1);
    name[sizeof(name) - 1] = '\0';
    strncpy(inf->name, name, NAMELEN);

    /* See resolve_handle() above: a ZERO source handle is the documented
     * general case and a refused dup is borrowed, not fatal.  Neither can
     * fail pthread_create any more, so there is no `goto out' here now --
     * only CreateNewProcTags can still fail below. */
    resolve_handle(&hpIn,  &fileIn,  Input(),       NP_Input,  "Input()");
    resolve_handle(&hpOut, &fileOut, Output(),      NP_Output, "Output()");
    resolve_handle(&hpErr, &fileErr, ErrorOutput(), NP_Error,  "ErrorOutput()");

    // start the child thread
    inf->task = CreateNewProcTags(
            NP_Start,                StarterFunc,
            NP_UserData,             inf,
            inf->attr.stacksize == 0 ? TAG_IGNORE : NP_StackSize, inf->attr.stacksize,
            NP_Name,                 name,
            NP_Child,                TRUE,
            /* NP_Close* spelled out and never TAG_IGNOREd -- their DOS
             * defaults are TRUE.  See resolve_handle() above. */
            hpIn.tag,                hpIn.fh,
            NP_CloseInput,           hpIn.close,
            hpOut.tag,               hpOut.fh,
            NP_CloseOutput,          hpOut.close,
            hpErr.tag,               hpErr.fh,
            NP_CloseError,           hpErr.close,
            NP_EntryData,			 newThreadMessage,
            TAG_DONE);

    /* Reached by fall-through only.  The former `out:' label is gone with the
     * DupFileHandle bail-out that was its only goto; CreateNewProcTags is now
     * the sole way pthread_create can fail here. */
    if (0 == inf->task) {
        if (fileIn)
            Close(fileIn);
        if (fileOut)
            Close(fileOut);
        if (fileErr)
            Close(fileErr);

    	if (inf->cancel_signal != -1) {
			FreeSignal(inf->cancel_signal);
			inf->cancel_signal = -1;
		}
        if (inf->join_signal != -1) {
            FreeSignal(inf->join_signal);
            inf->join_signal = -1;
        }
    	if (newThreadMessage != NULL) {
    		FreeSysObject(ASOT_MESSAGE, newThreadMessage);
    		newThreadMessage = NULL;
    	}
    	if (msgPort != NULL) {
    		FreeSysObject(ASOT_PORT, msgPort);
    		msgPort = NULL;
    	}
        _pthread_clear_threadinfo(inf); // Release the reserved slot back to IDLE
        MutexRelease(thread_sem);
        PTHREAD_CREATE_FAILED("CreateNewProcTags() returned 0");
        return EAGAIN;
    }

	WaitPort(msgPort);
	GetMsg(msgPort);

    *thread = threadnew;

	FreeSysObject(ASOT_MESSAGE, newThreadMessage);
	FreeSysObject(ASOT_PORT, msgPort);
	newThreadMessage = NULL;
	msgPort = NULL;

    MutexRelease(thread_sem);

    return OK;
}
