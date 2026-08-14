/*
 * $Id: mman_mprotect.c,v 1.0 2026-04-14 00:00:00 clib4devs Exp $
 *
 * mprotect() - set protection on a region of memory
 *
 * POSIX.1-2001 / SVr4.  See man mprotect(2).
 *
 * On AmigaOS 4 the MMU protection is enforced via exec.library's
 * SetMemoryAttrs(), which must be called in supervisor mode.  POSIX
 * protection flags are mapped to AmigaOS memory attribute flags:
 *
 *   PROT_NONE              -> MEMATTRF_SUPER_RW     (user: no access)
 *   PROT_READ (no write)   -> MEMATTRF_READ_ONLY    (user: read-only)
 *   PROT_WRITE / READ|WRITE-> MEMATTRF_READ_WRITE   (user: RW)
 *   PROT_EXEC              -> additionally set MEMATTRF_EXECUTE
 *
 * Non-protection MMU attributes (cache, coherency, etc.) are preserved
 * by reading the current attributes first and merging in the new bits.
 *
 * When the target pointer was returned by mmap(), the prot field of its
 * tracking header is also updated so that msync() / munmap() can make
 * informed decisions.
*/

#ifndef _UNISTD_HEADERS_H
#include "unistd_headers.h"
#endif /* _UNISTD_HEADERS_H */

#ifndef _STDLIB_MEMORY_H
#include "stdlib_memory.h"
#endif

#include <sys/mman.h>
#include <exec/memory.h>
#include <interfaces/exec.h>
#include <stdint.h>
#include "mmap_internal.h"

/*
 * Bits of a GetMemoryAttrs() result that are legitimately SETTABLE and that
 * we therefore carry across into the SetMemoryAttrs() call.  This is a
 * WHITELIST, not a blacklist, because exec/memory.h's attribute word mixes
 * three different kinds of bit and only one kind may be written back
 * (SDK exec/memory.h:192-226):
 *
 *   settable  MEMATTRF_WRITETHROUGH / CACHEINHIBIT / COHERENT / GUARDED
 *             (bits 0-3) -- cache and coherency policy.  Preserved here.
 *   status    MEMATTRF_REFERENCED / CHANGED (bits 4-5) -- hardware-maintained
 *             page state, and reported only when GetMemoryAttrs is called with
 *             GMAF_REPORT_CR.  We pass flags = 0, so they should never appear;
 *             masked anyway rather than relying on that.
 *   never     MEMATTRF_NOT_MAPPED (bit 10) is documented "only used as return
 *             value of GetMemoryAttr", and MEMATTRF_RESERVED1/2/3 (bits 11-13)
 *             are documented "Used by the system / _NEVER_ use these".
 *
 * The previous formulation (clear RW_MASK|EXECUTE, keep everything else) fed
 * NOT_MAPPED and the three reserved bits straight back into SetMemoryAttrs if
 * the MMU ever reported them.  Nothing observed required that; it was simply
 * unbounded.
 */
#define MPROTECT_PRESERVED_ATTRS \
    ((ULONG)(MEMATTRF_WRITETHROUGH | MEMATTRF_CACHEINHIBIT | \
             MEMATTRF_COHERENT     | MEMATTRF_GUARDED))

/*
 * Map POSIX prot flags to AmigaOS MMU memory-attribute bits, preserving
 * the cache/coherency policy bits from current_attrs.
 */
static ULONG
__prot_to_memattrf(int prot, ULONG current_attrs)
{
    /* Keep ONLY the settable cache/coherency policy; see the whitelist above. */
    ULONG attrs = current_attrs & MPROTECT_PRESERVED_ATTRS;

    if (prot == PROT_NONE) {
        /* User mode: no access; supervisor: R/W */
        attrs |= MEMATTRF_SUPER_RW;
    } else if (prot & PROT_WRITE) {
        /* User mode: read/write */
        attrs |= MEMATTRF_READ_WRITE;
    } else {
        /* PROT_READ and/or PROT_EXEC without PROT_WRITE: user read-only */
        attrs |= MEMATTRF_READ_ONLY;
    }

    if (prot & PROT_EXEC) {
        attrs |= MEMATTRF_EXECUTE;
    }

    return attrs;
}

int
mprotect(void *addr, size_t len, int prot)
{
    ENTER();

    SHOWPOINTER(addr);
    SHOWVALUE(len);
    SHOWVALUE(prot);

    /* addr must not be NULL */
    if (addr == NULL) {
        __set_errno(EINVAL);
        RETURN(-1);
        return -1;
    }

    /* A zero-length range is a no-op */
    if (len == 0) {
        RETURN(0);
        return 0;
    }

    /* addr must be page-aligned (POSIX requirement) */
    if ((uintptr_t)addr & (MMAP_PAGE_SIZE - 1)) {
        __set_errno(EINVAL);
        RETURN(-1);
        return -1;
    }

    /* Only valid POSIX prot flags are accepted */
    if ((unsigned int)prot & ~(unsigned int)(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM)) {
        __set_errno(EINVAL);
        RETURN(-1);
        return -1;
    }

    /*
     * Update mmap tracking data if this is a managed mmap region.
     *
     * The lookup goes through the authoritative __mmap_records list (under
     * the memory lock) instead of blindly reading a struct mmap_header at
     * (addr - sizeof(struct mmap_header)): for arbitrary caller pointers
     * that are NOT from our mmap() — e.g. pthread stack pages, whose
     * page-aligned base can sit at the very start of a dos.library stack
     * block — that raw read touches memory we do not own.  The in-page
     * header is only ever read at (rec->user_ptr - sizeof(header)), which
     * is always inside our own allocation.
     *
     * The header prot update happens INSIDE the locked walk: writing it
     * after __memory_unlock would race a concurrent munmap() (the record
     * and its backing pages could be freed between unlock and write).
     * Everything needed after the unlock is copied out under the lock; no
     * header access happens once the lock is dropped.
     */
    int prot_exec_denied = 0;
    {
        struct _clib4 *__clib4 = __CLIB4;
        struct mmap_record *rec;

        __memory_lock(__clib4);
        for (rec = __mmap_records; rec != NULL; rec = rec->next) {
            struct mmap_header *h = __mmap_get_header(rec->user_ptr);
            if (h == NULL)
                continue; /* corrupted in-page header — skip this record */
            if ((char *) addr >= (char *) rec->user_ptr &&
                (char *) addr < (char *) rec->user_ptr + h->length) {
                /*
                 * On AmigaOS 4 / E5500/MPC74xx, execute permission in the
                 * I-TLB is determined by the physical memory type set at
                 * allocation time.  Only memory allocated from the
                 * MEMF_EXECUTABLE pool can be executed; SetMemoryAttrs(
                 * MEMATTRF_EXECUTE) on memory from the non-exec pool is
                 * silently ignored by the hardware and results in an ISI
                 * (Instruction Storage Interrupt) at execution time.
                 *
                 * If the caller requests PROT_EXEC on a mapping that was
                 * NOT allocated from MEMF_EXECUTABLE (i.e. was allocated
                 * with mmap(prot without PROT_EXEC)), we cannot grant the
                 * request.  Return EACCES so the caller knows the operation
                 * is unsupported, rather than pretending to succeed and
                 * causing an ISI crash later.  To get an executable
                 * mapping, allocate with PROT_EXEC in the original mmap().
                 */
                if ((prot & PROT_EXEC) && !rec->exec_alloc)
                    prot_exec_denied = 1;
                else if (addr == rec->user_ptr)
                    h->prot = prot; /* base of the mapping: keep prot current */
                break;
            }
        }
        __memory_unlock(__clib4);
    }

    if (prot_exec_denied) {
        __set_errno(EACCES);
        RETURN(-1);
        return -1;
    }

    /*
     * Apply MMU protection via exec.library's MMU interface.
     *
     * GetMemoryAttrs / SetMemoryAttrs live in the "mmu" interface of
     * exec.library (struct MMUIFace), not in IExec.  We obtain it on
     * demand and release it immediately after use.
     *
     * Notes:
     *  - GetMemoryAttrs preserves cache/coherency flags when we merge bits.
     *  - SetMemoryAttrs silently ignores ranges that contain unmapped pages.
     *  - Both functions must be called in supervisor mode.
     *  - UserState() must only be called when SuperState() returned non-NULL.
     *
     * Probe-then-commit: before changing anything, GetMemoryAttrs is run on
     * every page in [addr, addr+len).  If any page reports MEMATTRF_NOT_MAPPED
     * the range is not fully described by the MMU — commit nothing and fail
     * with ENOMEM (POSIX allows ENOMEM for unmapped regions).  This turns what
     * would otherwise be a DSI inside SetMemoryAttrs into a clean, catchable
     * error.
     *
     * THE SENTINEL IS MEMATTRF_NOT_MAPPED, *NOT* attrs == 0.  This is the fix
     * for the gate 2f / R-3 regression, and the reason is arithmetic:
     *
     *     MEMATTRF_SUPER_RW = (0L << 6) = 0        (SDK exec/memory.h:209)
     *
     * PROT_NONE maps to MEMATTRF_SUPER_RW, i.e. to *no bits at all*.  A page
     * that this very function has just set to PROT_NONE, and whose cache
     * policy is the default (cacheable, copy-back, non-coherent, unguarded =
     * bits 0-3 clear), therefore reads back from GetMemoryAttrs as EXACTLY 0.
     *
     * The previous `attrs == 0 => invalid` test consequently rejected the
     * restore-from-PROT_NONE of a perfectly well-mapped page, which is
     * precisely the observed defect: S2 (restore from PROT_READ) passes
     * because MEMATTRF_READ_ONLY = MEMATTRF_SUPER_RO_USER_RO = 3<<6 = 0xC0 is
     * non-zero, while S3 (restore from PROT_NONE) failed with ENOMEM.  Only
     * the transition OUT OF no-access was affected, which is why the failure
     * looked so much narrower than "mprotect is broken".
     *
     * The correct sentinel is documented in the SDK header itself
     * (exec/memory.h:218-221):
     *
     *     MEMATTRF_NOT_MAPPED = (1L<<10)  "Special flag: The memory is not
     *         mapped at all. This flag is only used as return value of
     *         GetMemoryAttr"
     *
     * ASSUMPTION, NOT YET MEASURED: that GetMemoryAttrs actually sets
     * MEMATTRF_NOT_MAPPED for an unmapped VA rather than returning a bare 0.
     * The header says it does.  If it in fact returns 0, then 0 is ambiguous
     * between "unmapped" and "mapped, PROT_NONE, default cache policy", the
     * two cannot be told apart with GetMemoryAttrs alone, and this guard
     * cannot be made simultaneously safe and correct — a far more important
     * finding than the bug it is fixing.  mprotect_stack case S7 exists to
     * decide exactly this and has NOT been run.  Note the downside is bounded
     * either way: per the note above, SetMemoryAttrs silently ignores ranges
     * containing unmapped pages (itself an inherited claim, not measured).
     *
     * The probe is CHUNKED: supervisor state is held for at most
     * MPROTECT_PROBE_CHUNK_PAGES pages at a time (Super -> probe chunk ->
     * User, repeat).  A single SuperState span across a JVM-sized range
     * (50k-250k pages) would stall system-wide scheduling for the whole
     * walk.  The final SetMemoryAttrs commit uses its own short
     * SuperState/UserState pair, exactly as before.
     */
#define MPROTECT_PROBE_CHUNK_PAGES 256UL

    struct MMUIFace *IMMU = (struct MMUIFace *)
        GetInterface((struct Library *)IExec->Data.LibBase, "mmu", 1, NULL);

    if (IMMU != NULL) {
        ULONG current = 0;
        BOOL valid = TRUE;
        size_t off = 0;
        size_t bad_off = 0;
        ULONG bad_attrs = 0;
        APTR stack;

        while (valid && off < len) {
            size_t chunk_end = off + MPROTECT_PROBE_CHUNK_PAGES * MMAP_PAGE_SIZE;
            if (chunk_end > len)
                chunk_end = len;

            stack = SuperState();
            for (; off < chunk_end; off += MMAP_PAGE_SIZE) {
                ULONG attrs = GetMemoryAttrs((char *)addr + off, 0);
                if (attrs & (ULONG)MEMATTRF_NOT_MAPPED) {
                    valid = FALSE;
                    bad_off = off;
                    bad_attrs = attrs;
                    break;
                }
                if (off == 0)
                    current = attrs; /* merge cache/coherency bits from page 1 */
            }
            if (stack != NULL) {
                UserState(stack);
            }
        }
        if (valid) {
            stack = SuperState();
            SetMemoryAttrs(addr, (ULONG)len, __prot_to_memattrf(prot, current));
            if (stack != NULL) {
                UserState(stack);
            }
        }
        DropInterface((struct Interface *)IMMU);

        if (!valid) {
            /*
             * Say WHICH page and WHAT it reported.  A bare ENOMEM out of
             * mprotect() is what made gate 2f uninterpretable for five days:
             * the caller sees a POSIX errno that is indistinguishable from
             * "out of memory" and has no way to learn that a probe rejected
             * one specific page for one specific reason.  DebugPrintF from
             * library code is established practice here (precedent:
             * library/pthread/pthread_create.c:166, library/stdio/fread.c:248)
             * and lands in the serial log of a release build.
             */
            DebugPrintF("[clib4 mprotect] ENOMEM: page %p of range %p+%lu "
                        "reports MEMATTRF_NOT_MAPPED (attrs=0x%08lx); "
                        "prot=%d NOT applied to any page\n",
                        (char *)addr + bad_off, addr, (unsigned long)len,
                        (unsigned long)bad_attrs, prot);
            __set_errno(ENOMEM);
            RETURN(-1);
            return -1;
        }
    }

    RETURN(0);
    return 0;
}
