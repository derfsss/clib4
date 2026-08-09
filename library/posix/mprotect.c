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
 * Map POSIX prot flags to AmigaOS MMU memory-attribute bits, preserving
 * the non-protection bits from current_attrs (cache, coherency, etc.).
 */
static ULONG
__prot_to_memattrf(int prot, ULONG current_attrs)
{
    /* Strip only the protection-related bits; keep cache/coherency flags */
    ULONG attrs = current_attrs & ~((ULONG)(MEMATTRF_RW_MASK | MEMATTRF_EXECUTE));

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
     * every page in [addr, addr+len).  If any page reports no valid
     * attributes (0), the range is not fully described by the MMU — commit
     * nothing and fail with ENOMEM (POSIX allows ENOMEM for unmapped
     * regions).  This turns what would otherwise be a DSI inside
     * SetMemoryAttrs into a clean, catchable error.
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
        APTR stack;

        while (valid && off < len) {
            size_t chunk_end = off + MPROTECT_PROBE_CHUNK_PAGES * MMAP_PAGE_SIZE;
            if (chunk_end > len)
                chunk_end = len;

            stack = SuperState();
            for (; off < chunk_end; off += MMAP_PAGE_SIZE) {
                ULONG attrs = GetMemoryAttrs((char *)addr + off, 0);
                if (attrs == 0) {
                    valid = FALSE;
                    break;
                }
                if (off == 0)
                    current = attrs; /* merge non-protection bits from page 1 */
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
            __set_errno(ENOMEM);
            RETURN(-1);
            return -1;
        }
    }

    RETURN(0);
    return 0;
}
