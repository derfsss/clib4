/*
 * poll_timing -- does a blocking poll()/select() actually block?
 *
 * WHY THIS EXISTS
 * ---------------
 * R-16c on qemu-java (lab_logs/boot015): five successive 300 ms selects on an
 * idle java.nio Selector returned in 4 ms TOTAL.  Every NIO select loop on this
 * port therefore spins at 100% CPU.  The suspected mechanism is in clib4:
 * poll() stamps FDF_POLL on every descriptor it maps (library/posix/poll.c:64)
 * and library/socket/select_signal.c then declared every FDF_POLL descriptor
 * readable without asking the stream anything.
 *
 * [!] THE THING THIS PROBE EXISTS TO SETTLE is NOT "is poll fast".  It is:
 *
 *      P0 -- IS THERE A READINESS ORACLE FOR AN AmigaOS PIPE: AT ALL?
 *
 * The fix in select_signal.c replaces the unconditional "ready" with
 * ExamineObjectTags(EX_FileHandleInput) / FileSize.  If that call does not
 * work on PIPE:, the fix cannot work either -- it degrades safely back to the
 * old always-ready behaviour, but it fixes nothing.  P0 answers that question
 * directly and it is worth more than every other line of output here.
 *
 * [!] AND ONE ANSWER IS WORSE THAN A FAILURE: if Examine SUCCEEDS but reports
 * FileSize == 0 for a pipe that demonstrably HAS data (the "0 then 0" case in
 * P0), then the oracle lies, and a fix built on it would report "never ready"
 * and MISS WAKEUPS -- a hang, not a spin.  P0 prints both states side by side
 * precisely so that case cannot be mistaken for success.
 *
 * HOW TO READ THE TIMINGS
 * -----------------------
 * Every timed step prints  elapsed=<n>ms expect=<what>  and a verdict of
 * PASS / FAIL / INFO.  A timeout is honoured if elapsed is at least 60% of the
 * requested timeout.  "returned early" is the defect; the number is printed so
 * that 4 vs 300 is not a matter of opinion.
 *
 * SAFETY
 * ------
 * Steps P0..P7 and P9..P12 carry a bounded timeout in every poll() call, so
 * none of them can hang on a library whose loops honour their deadline.
 *
 * [!] P9 and P10 are the exception worth naming: they are the FIRST rows to
 * take the mixed socket+file branch with a {0,0} timeout, which before the
 * poll_once fix in that branch had no exit condition of its own and leaned on a
 * DateStamp tie.  If the run stops after "[P9] ..." with nothing following, the
 * mixed loop's zero-timeout exit is the answer.  P11a/P11/P12 open a loopback
 * TCP connection; if the stack cannot, they report NOT TESTED rather than FAIL.
 *
 * Step P8 is different again and is NOT run by default:
 *
 *      poll_timing hang
 *
 * runs P8, which is select(0, NULL, NULL, NULL, &{0,0}).  On a library without
 * the poll_once fix that call NEVER RETURNS -- the files-only loop consults its
 * deadline only when the timeout is non-zero, so a zero timeout leaves it with
 * no exit condition.  Ctrl-C still works (the loop calls __check_abort_f), but
 * do not run it unless you want to demonstrate that.
 *
 * Every line is flushed as it is produced, so a wedge names the step it wedged
 * in rather than losing the whole run.
 */

#define __USE_INLINE__
#include <proto/dos.h>
#include <proto/exec.h>
#include <dos/dos.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

/* A timeout counts as honoured if we waited at least this fraction of it.
 * Generous on purpose: DateStamp() has 1/50 s granularity, so a 300 ms wait
 * can legitimately come back at 280 ms.  4 ms is not a granularity effect. */
#define HONOURED_NUM 6
#define HONOURED_DEN 10

static int failures = 0;
static int unknowns = 0;

static void
say(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static long long
now_ms(void) {
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return -1;

    return (long long) tv.tv_sec * 1000LL + (long long) tv.tv_usec / 1000LL;
}

static void
verdict(const char *tag, int ok, const char *what) {
    if (ok) {
        say("[%s] PASS  %s\n", tag, what);
    } else {
        failures++;
        say("[%s] FAIL  %s\n", tag, what);
    }
}

static void
info(const char *tag, const char *what) {
    say("[%s] INFO  %s\n", tag, what);
}

/* Drain whatever is sitting in a non-blocking read end. Returns bytes drained. */
static int
drain(int fd) {
    char buf[64];
    int total = 0;

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        total += (int) n;
        if ((size_t) n < sizeof(buf))
            break;
    }

    return total;
}

/* ------------------------------------------------------------------ P0 ---
 * The oracle.  Two independent looks at the same question.
 *
 * P0a asks dos.library directly about a raw PIPE: handle: this measures the
 *     HANDLER, with nothing of clib4's in the way.
 * P0b asks fstat() about the read end of a real clib4 pipe().  fstat() routes
 *     through fdhookentry.c file_action_examine -> ExamineObjectTags(
 *     EX_FileHandleInput) and convertfileinfo.c:100 copies FileSize into
 *     st_size, so this is the SAME call on the SAME kind of handle that
 *     select_signal.c's file_input_state() will make.
 *
 * * P0b can be fooled where P0a cannot: when ExamineObjectTags fails with
 *   ERROR_ACTION_NOT_KNOWN on an interactive stream, fdhookentry.c fabricates
 *   an ExamineData with Type=ST_CONSOLE and FileSize=0 and returns SUCCESS.
 *   That is why both are here.  Believe P0a about whether the call works, and
 *   believe the pair of them about whether the number MOVES.
 */
static void
probe_oracle(int rfd, int wfd) {
    struct ExamineData *fib;
    struct stat st;
    BPTR raw_w = (BPTR) 0, raw_r = (BPTR) 0;
    char name[128];
    int64_t empty_size = -1, filled_size = -1;
    int empty_ok = 0, filled_ok = 0;
    int rc;

    say("\n=== P0  READINESS ORACLE FOR A PIPE ===\n");

    /* ---- P0a: raw dos.library on a raw PIPE: pair ---- */
    snprintf(name, sizeof(name), "PIPE:polltiming%lu/131072/0",
             (unsigned long) getpid());

    raw_w = Open(name, MODE_NEWFILE);
    raw_r = Open(name, MODE_OLDFILE);

    if (raw_w == (BPTR) 0 || raw_r == (BPTR) 0) {
        say("[P0a] INFO  cannot open %s (w=%ld r=%ld ioerr=%ld) -- skipped\n",
            name, (long) raw_w, (long) raw_r, (long) IoErr());
    } else {
        fib = ExamineObjectTags(EX_FileHandleInput, raw_r, TAG_DONE);
        if (fib == NULL) {
            say("[P0a] Examine(empty)  = NULL   ioerr=%ld\n", (long) IoErr());
        } else {
            empty_ok = 1;
            empty_size = (int64_t) fib->FileSize;
            say("[P0a] Examine(empty)  = OK     Type=%ld FileSize=%lld"
                " (ST_PIPEFILE=%ld)\n",
                (long) fib->Type, (long long) fib->FileSize, (long) ST_PIPEFILE);
            FreeDosObject(DOS_EXAMINEDATA, fib);
        }

        Write(raw_w, "ABCD", 4);

        fib = ExamineObjectTags(EX_FileHandleInput, raw_r, TAG_DONE);
        if (fib == NULL) {
            say("[P0a] Examine(4 bytes)= NULL   ioerr=%ld\n", (long) IoErr());
        } else {
            filled_ok = 1;
            filled_size = (int64_t) fib->FileSize;
            say("[P0a] Examine(4 bytes)= OK     Type=%ld FileSize=%lld\n",
                (long) fib->Type, (long long) fib->FileSize);
            FreeDosObject(DOS_EXAMINEDATA, fib);
        }

        say("[P0a] WaitForChar(empty-after-write, 1000us) = %ld\n",
            (long) WaitForChar(raw_r, 1000));

        Close(raw_r);
        Close(raw_w);

        if (!empty_ok || !filled_ok) {
            unknowns++;
            say("[P0a] VERDICT: NO ORACLE. ExamineObjectTags does not work on\n"
                "      PIPE:.  select_signal.c file_input_state() will return\n"
                "      FILE_INPUT_UNKNOWN, fall back to always-ready, and the\n"
                "      spin in R-16c WILL REMAIN.  A different oracle is needed.\n");
        } else if (empty_size == 0 && filled_size == 4) {
            say("[P0a] VERDICT: ORACLE GOOD. FileSize tracks queued bytes\n"
                "      (0 -> 4).  The select_signal.c fix has a sound basis.\n");
        } else if (empty_size == filled_size) {
            failures++;
            say("[P0a] VERDICT: [!] ORACLE LIES. Examine succeeds but FileSize\n"
                "      does not move (%lld -> %lld).  A fix built on it would\n"
                "      report 'never ready' and MISS WAKEUPS -- a hang, which\n"
                "      is worse than the spin.  DO NOT SHIP the Examine-based\n"
                "      oracle on this evidence.\n",
                (long long) empty_size, (long long) filled_size);
        } else {
            say("[P0a] VERDICT: ORACLE MOVES but not as expected (%lld -> %lld,\n"
                "      wrote 4).  Readable-vs-not is still decidable; the exact\n"
                "      byte count is not.  file_input_state() only tests != 0,\n"
                "      so this is sufficient -- record the numbers.\n",
                (long long) empty_size, (long long) filled_size);
        }
    }

    /* ---- P0b: fstat() on the real clib4 pipe fd ---- */
    memset(&st, 0, sizeof(st));
    errno = 0;
    rc = fstat(rfd, &st);
    say("[P0b] fstat(empty)   rc=%d errno=%d (%s) st_size=%lld\n",
        rc, errno, strerror(errno), (long long) st.st_size);

    if (write(wfd, "ABCD", 4) != 4)
        say("[P0b] INFO  write of 4 bytes into the clib4 pipe failed errno=%d\n", errno);

    memset(&st, 0, sizeof(st));
    errno = 0;
    rc = fstat(rfd, &st);
    say("[P0b] fstat(4 bytes) rc=%d errno=%d (%s) st_size=%lld\n",
        rc, errno, strerror(errno), (long long) st.st_size);

    say("[P0b] drained %d bytes\n", drain(rfd));
}

/* ------------------------------------------------------------------ P1 ---
 * The headline measurement: a blocking poll on an empty pipe.
 */
static void
probe_blocking_poll(int rfd) {
    struct pollfd p;
    long long t0, dt;
    int rc;

    say("\n=== P1  poll(pipe, POLLIN, 300) on an EMPTY pipe ===\n");

    p.fd = rfd;
    p.events = POLLIN;
    p.revents = 0;

    t0 = now_ms();
    rc = poll(&p, 1, 300);
    dt = now_ms() - t0;

    say("[P1] rc=%d revents=0x%x elapsed=%lldms expect>=%dms\n",
        rc, (unsigned) p.revents, dt, 300 * HONOURED_NUM / HONOURED_DEN);

    verdict("P1", dt >= (300 * HONOURED_NUM / HONOURED_DEN),
            "timeout honoured (returning early here IS R-16c)");
    verdict("P1", rc == 0, "rc==0: nothing was readable and poll said so");
}

/* ------------------------------------------------------------------ P2 ---
 * The non-blocking test, i.e. Java's selectNow().  Must return at once with 0.
 * [!] This is also the shape that HANGS on a library that fixed FDF_POLL without
 *   fixing the zero-timeout exit condition.  If the run stops here, that is the
 *   answer.
 */
static void
probe_zero_timeout(int rfd) {
    struct pollfd p;
    long long t0, dt;
    int rc;

    say("\n=== P2  poll(pipe, POLLIN, 0) on an EMPTY pipe (selectNow shape) ===\n");
    say("[P2] entering poll -- if this line is the last one printed, the\n"
        "     zero-timeout exit condition in select_signal.c is missing\n");

    p.fd = rfd;
    p.events = POLLIN;
    p.revents = 0;

    t0 = now_ms();
    rc = poll(&p, 1, 0);
    dt = now_ms() - t0;

    say("[P2] rc=%d revents=0x%x elapsed=%lldms expect<100ms\n",
        rc, (unsigned) p.revents, dt);

    verdict("P2", dt < 100, "returned promptly");
    verdict("P2", rc == 0 && p.revents == 0, "reported NOT ready on an empty pipe");
}

/* ------------------------------------------------------------------ P3 ---
 * The wakeup path.  A second thread writes one byte after ~400 ms, exactly as
 * Selector.wakeup() -> IOUtil.write1 does.  poll must be asleep and must be
 * woken.  [!] A fix that breaks THIS is worse than the bug it fixed.
 */
struct waker_arg {
    int fd;
    unsigned delay_ms;
};

static void *
waker(void *v) {
    struct waker_arg *a = (struct waker_arg *) v;

    usleep(a->delay_ms * 1000u);
    if (write(a->fd, "W", 1) != 1)
        say("[P3] INFO  waker thread write failed errno=%d\n", errno);

    return NULL;
}

static void
probe_wakeup(int rfd, int wfd) {
    struct waker_arg arg;
    pthread_t th;
    struct pollfd p;
    long long t0, dt;
    int rc, drained;

    say("\n=== P3  poll(pipe, POLLIN, 2000), one byte written at ~400ms ===\n");

    arg.fd = wfd;
    arg.delay_ms = 400;

    if (pthread_create(&th, NULL, waker, &arg) != 0) {
        info("P3", "pthread_create failed -- wakeup path NOT TESTED");
        unknowns++;
        return;
    }

    p.fd = rfd;
    p.events = POLLIN;
    p.revents = 0;

    t0 = now_ms();
    rc = poll(&p, 1, 2000);
    dt = now_ms() - t0;

    say("[P3] rc=%d revents=0x%x elapsed=%lldms expect 250..1200ms\n",
        rc, (unsigned) p.revents, dt);

    /* Read AFTER the poll and BEFORE joining the waker: if poll returned
     * because it was told the pipe was ready, a read must find the byte.
     * Without this check "revents & POLLIN" is not evidence of anything --
     * on the unfixed library POLLIN is set unconditionally, so a verdict
     * based on revents alone is a test that cannot fail.  That is the same
     * hole that makes gate R-16f a weak witness. */
    drained = drain(rfd);

    pthread_join(th, NULL);

    say("[P3] bytes actually readable when poll returned: %d\n", drained);

    verdict("P3", rc >= 1 && (p.revents & POLLIN) != 0 && drained >= 1,
            "poll said readable AND a byte was really there (R-16f's property,"
            " tested so that it can fail)");
    verdict("P3", dt >= 250 && dt <= 1200,
            "woken by the byte, not by the timeout and not instantly");

    say("[P3] drained %d further bytes\n", drain(rfd));
}

/* ------------------------------------------------------------------ P4 ---
 * Data already present: poll with a zero timeout must say so at once.
 */
static void
probe_ready_now(int rfd, int wfd) {
    struct pollfd p;
    long long t0, dt;
    int rc, drained;

    say("\n=== P4  poll(pipe, POLLIN, 0) with a byte ALREADY in the pipe ===\n");

    if (write(wfd, "R", 1) != 1) {
        info("P4", "write failed -- NOT TESTED");
        unknowns++;
        return;
    }

    p.fd = rfd;
    p.events = POLLIN;
    p.revents = 0;

    t0 = now_ms();
    rc = poll(&p, 1, 0);
    dt = now_ms() - t0;

    say("[P4] rc=%d revents=0x%x elapsed=%lldms\n", rc, (unsigned) p.revents, dt);

    drained = drain(rfd);
    say("[P4] bytes actually readable: %d (1 was written)\n", drained);

    verdict("P4", rc >= 1 && (p.revents & POLLIN) != 0 && drained == 1,
            "readable data is reported readable, and was really there");
}

/* ------------------------------------------------------------------ P5 ---
 * POLLNVAL survival.  map_poll_spec sets it (poll.c:42); map_select_results
 * used to overwrite it with 0 (poll.c:150).
 */
static void
probe_pollnval(int rfd) {
    struct pollfd p[2];
    long long t0, dt;
    int rc;

    say("\n=== P5  poll() over a valid pipe and a bad descriptor ===\n");

    p[0].fd = rfd;
    p[0].events = POLLIN;
    p[0].revents = 0x1234;   /* deliberate garbage: revents is output-only */
    p[1].fd = 500;           /* never opened */
    p[1].events = POLLIN;
    p[1].revents = 0x1234;

    t0 = now_ms();
    rc = poll(p, 2, 300);
    dt = now_ms() - t0;

    say("[P5] rc=%d pipe.revents=0x%x bad.revents=0x%x elapsed=%lldms\n",
        rc, (unsigned) p[0].revents, (unsigned) p[1].revents, dt);

    verdict("P5", (p[1].revents & POLLNVAL) != 0,
            "the bad descriptor reports POLLNVAL rather than silence");
    verdict("P5", rc >= 1, "POLLNVAL is counted in the return value");
    verdict("P5", dt < 100,
            "a bad descriptor does not cost the caller its whole timeout");
    verdict("P5", p[0].revents != 0x1234,
            "revents of the valid descriptor was written, not left alone");
}

/* ------------------------------------------------------------------ P6/P7 -
 * The mixed socket+file path, a different branch of __select() from the one
 * P1..P4 exercise.  It had its own defect: a poll()'d descriptor's readability
 * was taken from WaitForChar(Input()) -- the PROCESS'S STDIN -- rather than
 * from the descriptor's own handle.
 *
 * * Gate R-16f ("wakeup seen") CANNOT refute that: if the selector had no
 *   sockets registered it took the files-only path, where the old code called
 *   everything ready, so "wakeup seen" was guaranteed and could not have
 *   failed.  P7 is the test that CAN fail.
 *
 * P6: socket + pipe, both idle, 300 ms  -> must block ~300 ms.
 * P7: socket + pipe, pipe HAS a byte    -> must report the pipe readable.
 *     [!] If P7 fails while P4 passes, the mixed FDF_POLL arm is implicated and
 *     the fix is to use the descriptor's own handle there.
 *
 * STATUS: P7 FAILED on qemu-java (boot017/018/019) while P4 passed, twice, with
 * the byte demonstrably readable afterwards.  That is R-25.  The fix is in
 * select_signal.c:856-865 -- file_input_state(fd, i), the same oracle the
 * files-only arm uses at :1078.  P7 is now a REGRESSION row: a red P7 on a
 * library carrying that fix refutes it outright.
 */
static void
probe_mixed(int rfd, int wfd) {
    struct pollfd p[2];
    struct sockaddr_in sa;
    long long t0, dt;
    int s, rc;

    say("\n=== P6/P7  mixed socket + pipe (select_signal.c:685-852) ===\n");

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        say("[P6] INFO  socket() failed errno=%d (%s) -- mixed path NOT TESTED\n",
            errno, strerror(errno));
        unknowns++;
        return;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;                          /* let the stack choose */
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s, (struct sockaddr *) &sa, sizeof(sa)) < 0 || listen(s, 1) < 0) {
        say("[P6] INFO  bind/listen failed errno=%d (%s) -- mixed path NOT TESTED\n",
            errno, strerror(errno));
        close(s);
        unknowns++;
        return;
    }

    /* P6 -- both idle. */
    p[0].fd = s;   p[0].events = POLLIN; p[0].revents = 0;
    p[1].fd = rfd; p[1].events = POLLIN; p[1].revents = 0;

    t0 = now_ms();
    rc = poll(p, 2, 300);
    dt = now_ms() - t0;

    say("[P6] rc=%d sock.revents=0x%x pipe.revents=0x%x elapsed=%lldms expect>=%dms\n",
        rc, (unsigned) p[0].revents, (unsigned) p[1].revents, dt,
        300 * HONOURED_NUM / HONOURED_DEN);

    verdict("P6", dt >= (300 * HONOURED_NUM / HONOURED_DEN),
            "mixed path honours its timeout when nothing is ready");
    verdict("P6", rc == 0, "mixed path reports nothing ready when nothing is");

    /* P7 -- the pipe has data.  THE :746-750 DISCRIMINATOR. */
    if (write(wfd, "M", 1) != 1) {
        info("P7", "write failed -- NOT TESTED");
        unknowns++;
        close(s);
        return;
    }

    p[0].fd = s;   p[0].events = POLLIN; p[0].revents = 0;
    p[1].fd = rfd; p[1].events = POLLIN; p[1].revents = 0;

    t0 = now_ms();
    rc = poll(p, 2, 300);
    dt = now_ms() - t0;

    say("[P7] rc=%d sock.revents=0x%x pipe.revents=0x%x elapsed=%lldms\n",
        rc, (unsigned) p[0].revents, (unsigned) p[1].revents, dt);

    if ((p[1].revents & POLLIN) == 0) {
        failures++;
        say("[P7] FAIL  [!] the mixed path did NOT see data in the pipe.\n"
            "     If P4 passed and this failed, select_signal.c:746-750 is\n"
            "     implicated: it asks WaitForChar(Input()) -- the process's\n"
            "     stdin -- instead of the descriptor's own handle.  With a\n"
            "     socket registered, Selector.wakeup() is LOST.\n");
    } else {
        verdict("P7", 1, "the mixed path sees data in the pipe (:746-750 is NOT implicated)");
        verdict("P7", dt < 100, "and reports it without waiting out the timeout");
    }

    say("[P7] bytes actually readable: %d (1 was written)\n", drain(rfd));
    close(s);
}

/* ---------------------------------------------------------------- P9..P12 -
 * The mixed path under a ZERO timeout, and the proof that fixing the pipe did
 * not cost us the socket.
 *
 * P6/P7 above both use a 300 ms timeout, so neither of them touches the branch
 * that a mixed selectNow() takes.  Before the widening, a mixed select with a
 * {0,0} timeout fell through to the sockets-only arm of __select, which never
 * looks at the file sets at all -- and because those sets still hold everything
 * that was mapped into them, remap_descriptor_sets() reported EVERY file
 * descriptor ready.  P10 is the row that sees that: an empty pipe reported
 * readable is the old behaviour, not the new one.
 *
 * [!] AND THE ROW THAT MATTERS MOST HERE IS P11, because a "fix" for P7 that
 * made the pipe visible by breaking socket readiness would be worse than R-25
 * ever was.  P11 is deliberately paired with P11a, a SOCKETS-ONLY poll on the
 * same listener, which goes down the arm of __select that was not touched:
 *
 *      P11a ready, P11 not  -> the MIXED path lost the socket.  Convicted.
 *      P11a not ready       -> the connection never landed.  Says nothing about
 *                              select at all; P11/P12 are reported UNTESTED.
 *
 * Without P11a a red P11 cannot be told apart from a loopback stack that does
 * not complete a handshake, and the wrong conclusion is the attractive one.
 *
 * The client connection is made ONCE and left un-accepted, so the listener
 * stays readable across P11a, P11 and P12.
 */
static void
probe_mixed_zero_timeout(int rfd, int wfd) {
    struct pollfd p[2];
    struct sockaddr_in sa;
    socklen_t salen;
    long long t0, dt;
    int s = -1, c = -1, a = -1;
    int rc, drained, sock_ready;

    say("\n=== P9..P12  mixed socket + pipe, zero timeout and socket readiness ===\n");

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        say("[P9] INFO  socket() failed errno=%d (%s) -- NOT TESTED\n",
            errno, strerror(errno));
        unknowns++;
        return;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s, (struct sockaddr *) &sa, sizeof(sa)) < 0 || listen(s, 1) < 0) {
        say("[P9] INFO  bind/listen failed errno=%d (%s) -- NOT TESTED\n",
            errno, strerror(errno));
        close(s);
        unknowns++;
        return;
    }

    /* ---- P9: mixed selectNow, byte ALREADY in the pipe ---- */
    if (write(wfd, "Z", 1) != 1) {
        info("P9", "write failed -- NOT TESTED");
        unknowns++;
        close(s);
        return;
    }

    p[0].fd = s;   p[0].events = POLLIN; p[0].revents = 0;
    p[1].fd = rfd; p[1].events = POLLIN; p[1].revents = 0;

    t0 = now_ms();
    rc = poll(p, 2, 0);
    dt = now_ms() - t0;

    say("[P9] rc=%d sock.revents=0x%x pipe.revents=0x%x elapsed=%lldms\n",
        rc, (unsigned) p[0].revents, (unsigned) p[1].revents, dt);

    drained = drain(rfd);
    say("[P9] bytes actually readable: %d (1 was written)\n", drained);

    verdict("P9", dt < 100, "a mixed selectNow returns at once (a hang here is "
                            "the {0,0} exit condition in the mixed loop)");
    verdict("P9", (p[1].revents & POLLIN) != 0 && drained == 1,
            "a mixed selectNow sees the byte in the pipe -- this is the shape "
            "Selector.selectNow() uses to collect a pending wakeup");
    verdict("P9", rc >= 1,
            "and COUNTS it: rc must agree with the bits it set");

    /* ---- P10: mixed selectNow, pipe EMPTY ---- */
    p[0].fd = s;   p[0].events = POLLIN; p[0].revents = 0;
    p[1].fd = rfd; p[1].events = POLLIN; p[1].revents = 0;

    t0 = now_ms();
    rc = poll(p, 2, 0);
    dt = now_ms() - t0;

    say("[P10] rc=%d sock.revents=0x%x pipe.revents=0x%x elapsed=%lldms\n",
        rc, (unsigned) p[0].revents, (unsigned) p[1].revents, dt);

    verdict("P10", dt < 100, "returns at once");
    verdict("P10", (p[1].revents & POLLIN) == 0,
            "[!] an EMPTY pipe is NOT reported readable.  Failing here means the "
            "mixed zero-timeout case is still falling through to the "
            "sockets-only arm, which reports every mapped file ready");
    verdict("P10", rc == 0, "and rc == 0 agrees with that");

    /* ---- bring a real connection in, once, and leave it un-accepted ---- */
    salen = sizeof(sa);
    memset(&sa, 0, sizeof(sa));
    if (getsockname(s, (struct sockaddr *) &sa, &salen) < 0) {
        say("[P11] INFO  getsockname failed errno=%d (%s) -- socket-readiness "
            "rows NOT TESTED\n", errno, strerror(errno));
        unknowns++;
        close(s);
        return;
    }

    say("[P11] listener bound to 127.0.0.1:%u\n", (unsigned) ntohs(sa.sin_port));

    c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) {
        say("[P11] INFO  client socket() failed errno=%d (%s) -- NOT TESTED\n",
            errno, strerror(errno));
        unknowns++;
        close(s);
        return;
    }

    if (connect(c, (struct sockaddr *) &sa, sizeof(sa)) < 0 && errno != EINPROGRESS) {
        say("[P11] INFO  connect to loopback failed errno=%d (%s) -- socket "
            "readiness NOT TESTED (this says nothing about select)\n",
            errno, strerror(errno));
        unknowns++;
        close(c);
        close(s);
        return;
    }

    /* ---- P11a: the CONTROL.  Sockets only, so it takes the arm of __select
     *      that neither change touched. ---- */
    p[0].fd = s; p[0].events = POLLIN; p[0].revents = 0;

    t0 = now_ms();
    rc = poll(p, 1, 1000);
    dt = now_ms() - t0;

    sock_ready = (rc >= 1 && (p[0].revents & POLLIN) != 0);

    say("[P11a] sockets-only poll(listener, 1000): rc=%d revents=0x%x "
        "elapsed=%lldms\n", rc, (unsigned) p[0].revents, dt);

    if (!sock_ready) {
        say("[P11a] INFO  the connection never made the listener readable on the "
            "UNTOUCHED sockets-only path.  P11/P12 are therefore NOT TESTED: a "
            "red P11 here would measure the network stack, not select().\n");
        unknowns++;
        close(c);
        close(s);
        return;
    }

    /* ---- P11: the same question through the MIXED path, pipe empty ---- */
    p[0].fd = s;   p[0].events = POLLIN; p[0].revents = 0;
    p[1].fd = rfd; p[1].events = POLLIN; p[1].revents = 0;

    t0 = now_ms();
    rc = poll(p, 2, 1000);
    dt = now_ms() - t0;

    say("[P11] mixed poll(listener+pipe, 1000): rc=%d sock.revents=0x%x "
        "pipe.revents=0x%x elapsed=%lldms\n",
        rc, (unsigned) p[0].revents, (unsigned) p[1].revents, dt);

    verdict("P11", (p[0].revents & POLLIN) != 0,
            "[!] the mixed path still sees a READY SOCKET.  P11a proved the "
            "socket is ready; failing here means fixing the pipe cost us the "
            "socket, which is worse than R-25");
    verdict("P11", (p[1].revents & POLLIN) == 0,
            "and does not invent readiness for the empty pipe alongside it");

    /* ---- P12: both ready at once, zero timeout ---- */
    if (write(wfd, "B", 1) != 1) {
        info("P12", "write failed -- NOT TESTED");
        unknowns++;
    } else {
        p[0].fd = s;   p[0].events = POLLIN; p[0].revents = 0;
        p[1].fd = rfd; p[1].events = POLLIN; p[1].revents = 0;

        t0 = now_ms();
        rc = poll(p, 2, 0);
        dt = now_ms() - t0;

        say("[P12] rc=%d sock.revents=0x%x pipe.revents=0x%x elapsed=%lldms\n",
            rc, (unsigned) p[0].revents, (unsigned) p[1].revents, dt);

        drained = drain(rfd);
        say("[P12] bytes actually readable: %d (1 was written)\n", drained);

        verdict("P12", (p[0].revents & POLLIN) != 0 && (p[1].revents & POLLIN) != 0,
                "a zero-timeout mixed poll reports BOTH ready descriptors");
        verdict("P12", rc == 2, "and counts both of them");
        verdict("P12", dt < 100, "without waiting");
    }

    a = accept(s, NULL, NULL);
    if (a >= 0)
        close(a);
    close(c);
    close(s);
}

/* ------------------------------------------------------------------ P8 ---
 * [!] OPT-IN ONLY.  Hangs forever on a library without the zero-timeout fix.
 */
static void
probe_empty_select_zero_timeout(void) {
    struct timeval tv;
    long long t0, dt;
    int rc;

    say("\n=== P8  select(0, NULL, NULL, NULL, &{0,0})  [opt-in] ===\n");
    say("[P8] entering select -- on an unfixed library this NEVER RETURNS.\n"
        "     Ctrl-C works (__check_abort_f runs at the top of the loop).\n");

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    t0 = now_ms();
    rc = select(0, NULL, NULL, NULL, &tv);
    dt = now_ms() - t0;

    say("[P8] rc=%d elapsed=%lldms\n", rc, dt);
    verdict("P8", rc == 0 && dt < 100, "a zero-timeout select with no descriptors returns");
}

int
main(int argc, char **argv) {
    int fds[2];
    int run_hang = (argc > 1 && strcmp(argv[1], "hang") == 0);

    setvbuf(stdout, NULL, _IONBF, 0);

    say("=== poll_timing: does a blocking poll actually block? ===\n");
    say("build: %s %s\n", __DATE__, __TIME__);

    if (pipe(fds) != 0) {
        say("FATAL: pipe() failed errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    say("pipe: read fd=%d write fd=%d\n", fds[0], fds[1]);

    /* PollSelectorImpl uses IOUtil.makePipe(false): both ends non-blocking. */
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0)
        say("INFO: could not set O_NONBLOCK on the read end, errno=%d\n", errno);
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) < 0)
        say("INFO: could not set O_NONBLOCK on the write end, errno=%d\n", errno);

    probe_oracle(fds[0], fds[1]);
    probe_blocking_poll(fds[0]);
    probe_zero_timeout(fds[0]);
    probe_wakeup(fds[0], fds[1]);
    probe_ready_now(fds[0], fds[1]);
    probe_pollnval(fds[0]);
    probe_mixed(fds[0], fds[1]);
    probe_mixed_zero_timeout(fds[0], fds[1]);

    if (run_hang)
        probe_empty_select_zero_timeout();
    else
        say("\n=== P8 skipped (run `poll_timing hang` to include it) ===\n");

    close(fds[0]);
    close(fds[1]);

    say("\n=== SUMMARY: %d failure(s), %d untested/unknown ===\n", failures, unknowns);
    say("=== poll_timing done ===\n");

    return failures == 0 ? 0 : 1;
}
