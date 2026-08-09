/*
 * $Id: mman_mmap.c,v 1.1 2026-04-14 00:00:00 clib4devs Exp $
*/

#ifndef _UNISTD_HEADERS_H
#include "unistd_headers.h"
#endif /* _UNISTD_HEADERS_H */

#include <sys/mman.h>
#include <proto/exec.h>
#include <exec/memory.h>
#include <interfaces/exec.h>
#include "mmap_internal.h"

#ifndef _STDLIB_MEMORY_H
#include "stdlib_memory.h"
#endif

#ifndef _STDLIB_CONSTRUCTOR_H
#include "stdlib_constructor.h"
#endif /* _STDLIB_CONSTRUCTOR_H */

/* Process-global tracking list — one entry per live mmap() allocation.
 * Protected by the clib4 memory mutex (__memory_lock/__memory_unlock).
 * Defined here (mmap.c) and declared extern in mmap_internal.h.           */
struct mmap_record * volatile __mmap_records = NULL;

void *
mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    ENTER();

    SHOWPOINTER(addr);
    SHOWVALUE(len);
    SHOWVALUE(prot);
    SHOWVALUE(flags);
    SHOWVALUE(fd);
    SHOWVALUE(offset);

    if (len == 0) {
        __set_errno(EINVAL);
        errno = EINVAL;
        RETURN(MAP_FAILED);
        return MAP_FAILED;
    }

    /*
     * Allocate a page-aligned block with space for our tracking header.
     * Layout:
     *   [alloc_base ... alloc_base+PAGE_SIZE-1] <- header page (header sits
     *                                              at end of this page)
     *   [user_ptr ... user_ptr+len-1]           <- user data (page-aligned)
     *
     * This ensures the returned pointer satisfies POSIX page-alignment
     * requirements and that mprotect() can be safely applied to it.
     *
     * When PROT_EXEC is requested we use IExec->AllocVecTags() with
     * MEMF_EXECUTABLE so the E5500 I-TLB permits instruction fetch.
     * Otherwise we use the faster memalign() path.
     */
    size_t alloc_size = MMAP_PAGE_SIZE + len;
    int exec_alloc = 0;
    void *block;

    if (prot & PROT_EXEC) {
        /*
         * MEMF_EXECUTABLE is the only flag that guarantees the E5500/MPC74xx
         * I-TLB will permit instruction fetch from these pages.
         * MEMF_SHARED or MEMF_PRIVATE combined with MEMF_EXECUTABLE fail for
         * small allocations and are not needed — MEMF_EXECUTABLE alone works.
         * AVT_ClearWithValue is also omitted: AllocVecTags with MEMF_EXECUTABLE
         * already zeroes the block, and passing AVT_ClearWithValue can cause
         * alloc failures on some exec-pool implementations.
         */
        block = AllocVecTags(alloc_size,
                    AVT_Type,      MEMF_EXECUTABLE,
                    AVT_Alignment, MMAP_PAGE_SIZE,
                    TAG_DONE);
        exec_alloc = 1;
    } else {
        /*
         * Use AllocVecTags(MEMF_SHARED) directly — NOT memalign() — so that
         * mmap allocations live completely outside the wmem heap.  This prevents
         * any interaction with the wmem block/strict/simple allocator state
         * (including jumbo-alloc metadata, canary zones, pre_t pointers etc.)
         * regardless of which CLIB4_MEMORY_ALLOCATOR is active.
         */
        block = AllocVecTags(alloc_size,
                    AVT_Type,      MEMF_SHARED,
                    AVT_Alignment, MMAP_PAGE_SIZE,
                    TAG_DONE);
        exec_alloc = 0;
    }

    if (block == NULL) {
        __set_errno(ENOMEM);
        RETURN(MAP_FAILED);
        return MAP_FAILED;
    }
    /* AllocVecTags(MEMF_SHARED) zeroes automatically; only MEMF_EXECUTABLE
     * blocks need explicit zeroing at this point (already done by hardware). */
    if (!exec_alloc)
        memset(block, 0, alloc_size);

    /* Place header just before the page-aligned user pointer */
    void *user_ptr = (char *)block + MMAP_PAGE_SIZE;
    struct mmap_header *hdr = (struct mmap_header *)((char *)user_ptr - sizeof(struct mmap_header));

    /* Fill in the tracking header */
    hdr->magic      = MMAP_MAGIC;
    hdr->alloc_base = block;
    hdr->offset     = offset;
    hdr->length     = len;
    hdr->flags      = flags;
    hdr->prot       = prot;
    hdr->exec_alloc = exec_alloc;
    hdr->fd         = -1;

    if (fd >= 0) {
        /* File-backed mapping: dup the fd so caller can close theirs */
        int dfd = dup(fd);
        if (dfd < 0) {
            FreeVec(block);
            __set_errno(ENOMEM);
            RETURN(MAP_FAILED);
            return MAP_FAILED;
        }
        hdr->fd = dfd;

        /* Read file content into the mapping */
        lseek(dfd, offset, SEEK_SET);
        read(dfd, user_ptr, len);
    }

    (void)addr; /* MAP_FIXED not yet supported; addr hint is ignored */

    /*
     * We intentionally do NOT call mprotect() here for non-exec mappings.
     *
     * Rationale:
     *   - For PROT_EXEC mappings the E5500 I-TLB permission is already
     *     established by AllocVecTags(MEMF_EXECUTABLE).  SpiderMonkey
     *     calls mprotect() explicitly via CommitPages/ReprotectRegion
     *     when it needs to transition between RW and RX, so we must not
     *     duplicate that call here and risk mismatching MMU state.
     *
     *   - For file-backed (fd >= 0) and anonymous PROT_READ-only mappings,
     *     calling SetMemoryAttrs(MEMATTRF_READ_ONLY) on MEMF_SHARED memory
     *     sets the MMU page to read-only system-wide.  When exec.library
     *     later tries to reclaim those physical pages via FreeVec it may
     *     write a free-list pointer into the now-read-only page and trigger
     *     a DSI in kernel context — which on AmigaOS 4 silently suspends
     *     the offending task, manifesting as a hang rather than a crash.
     *
     * hdr->prot is still set correctly above so that msync/munmap
     * write-back decisions remain accurate.
     */

    /*
     * Register this allocation in the global tracking list so that
     * munmap() can safely free the correct alloc_base regardless of
     * whether the in-page header has been corrupted or is a false
     * positive match (e.g. file content that happens to start with
     * the MMAP_MAGIC bytes).
     *
     * IMPORTANT: use AllocVecTags(MEMF_SHARED) directly — NOT malloc() —
     * so that the tracking record lives outside the wmem heap.  This
     * avoids any risk of corrupting or triggering the wmem block/strict
     * allocator state while mmap() / munmap() are in progress.
     */
    struct mmap_record *rec = AllocVecTags(sizeof(*rec),
                                           AVT_Type, MEMF_SHARED,
                                           TAG_DONE);
    if (rec) {
        rec->user_ptr   = user_ptr;
        rec->alloc_base = block;
        rec->exec_alloc = exec_alloc;
        rec->fd         = hdr->fd;
        rec->owner      = __CLIB4;
        rec->owner_pid  = __CLIB4 ? (uint32_t) __CLIB4->processId : 0;
        rec->next       = NULL;
        __memory_lock(__CLIB4);
        rec->next       = __mmap_records;
        __mmap_records  = rec;
        __memory_unlock(__CLIB4);
    }
    /* If AllocVecTags fails we fall back to the in-page header (best-effort). */

    RETURN(user_ptr);
    return user_ptr;
}

/*
 * Restore MEMATTRF_READ_WRITE over a mapping's user pages before its backing
 * block is FreeVec'd.
 *
 * If the process mprotect()'d pages inside the mapping (e.g. guard pages) to
 * PROT_READ or PROT_NONE and the block is then FreeVec'd, exec.library may
 * later write free-list metadata into those still-protected pages from
 * kernel context — a DSI that silently suspends the task (the same hazard
 * the "do NOT mprotect here" comment in mmap() describes).
 *
 * The check reads the validated in-page header at (user_ptr - header size)
 * — the same pattern mprotect() uses — which lives in our own header page
 * and is never itself protected.  Kept cheap: the MMU interface is only
 * touched when hdr->prot lost PROT_WRITE (PROT_WRITE always maps to
 * MEMATTRF_READ_WRITE, so RW mappings — the overwhelmingly common case —
 * need no work).  An unreadable/invalid header skips the restore and the
 * free proceeds exactly as before.
 *
 * The MMU sequence (GetInterface "mmu" / SuperState / SetMemoryAttrs /
 * UserState / DropInterface, with UserState only when SuperState returned
 * non-NULL) mirrors mprotect() exactly.
 */
void
__mmap_restore_rw(void *user_ptr) {
    struct mmap_header *hdr = __mmap_get_header(user_ptr);

    if (hdr == NULL)
        return;     /* header unreadable/invalid: free as-is (old behavior) */
    if (hdr->prot & PROT_WRITE)
        return;     /* MMU already MEMATTRF_READ_WRITE — common case */

    struct MMUIFace *IMMU = (struct MMUIFace *)
        GetInterface((struct Library *)IExec->Data.LibBase, "mmu", 1, NULL);

    if (IMMU != NULL) {
        APTR stack = SuperState();
        ULONG current = GetMemoryAttrs(user_ptr, 0);
        if (current != 0) {
            /* Keep cache/coherency/execute bits; force the RW field to RW */
            ULONG attrs = (current & ~((ULONG)MEMATTRF_RW_MASK)) | MEMATTRF_READ_WRITE;
            SetMemoryAttrs(user_ptr, (ULONG)hdr->length, attrs);
        }
        if (stack != NULL) {
            UserState(stack);
        }
        DropInterface((struct Interface *)IMMU);
    }
}

/*
 * Free every tracking record (and its AllocVecTags backing block) that was
 * created by the given per-process context.
 *
 * Rationale: AllocVecTags memory has no per-process resource tracking on
 * AmigaOS — it survives process exit until explicitly freed.  In the
 * clib4.library build __mmap_records is a single system-wide list, so any
 * mapping a process failed to munmap() (including "unmapped" interior
 * pointers, which munmap() silently ignores) would otherwise leak until
 * reboot.
 */
void
__mmap_records_free_for(struct _clib4 *owner) {
    struct mmap_record * volatile *pp;
    struct mmap_record *rec;
    struct _clib4 *__clib4 = __CLIB4;

    ENTER();

    SHOWPOINTER(owner);

    __memory_lock(__clib4);     /* takes the system-global semaphore too */
    pp = &__mmap_records;
    while ((rec = *pp) != NULL) {
        if (rec->owner == owner) {
            *pp = rec->next;
            D(("freeing leaked mmap record %p (user_ptr=%p, pid=%lu)",
               rec, rec->user_ptr, (unsigned long) rec->owner_pid));
            /* Do NOT close(rec->fd) here: the dup'd fd belongs to the dying
             * process's fd table, which its own fd teardown closes; calling
             * close() from a destructor risks ordering hazards vs FILE dtors. */
            /* If the process left pages inside this mapping under restrictive
             * MMU protection (guard pages it never munmap'd), FreeVec on them
             * would DSI in kernel context — restore RW first. */
            __mmap_restore_rw(rec->user_ptr);
            FreeVec(rec->alloc_base);
            FreeVec(rec);
        } else {
            pp = &rec->next;
        }
    }
    __memory_unlock(__clib4);

    LEAVE();
}

STDLIB_DESTRUCTOR(stdlib_mmap_exit) {
    ENTER();
    struct _clib4 *__clib4 = __CLIB4;

    if (__clib4 != NULL)
        __mmap_records_free_for(__clib4);

    LEAVE();
}