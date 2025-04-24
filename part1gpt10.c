#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* Page constants */
#define PAGE_SIZE    4096
#define PGD_SHIFT    39
#define PUD_SHIFT    30
#define PMD_SHIFT    21
#define PTE_SHIFT    12
#define PTRS_PER_PT  512ULL

/* Regions for PFN allocation */
#define USER_REG      0
#define OS_PT_REG     1

/* Page-fault error codes */
#define ERR_CODE_READ    0x4
#define ERR_CODE_WRITE   0x6
#define ERR_CODE_PROT    0x7

/* PTE flag bits */
#define PTE_P   (1ULL << 0)
#define PTE_W   (1ULL << 1)
#define PTE_U   (1ULL << 2)

/* Helpers */
static inline u64 va_to_index(u64 va, int shift) {
    return (va >> shift) & (PTRS_PER_PT - 1);
}

static u64 align_length(u64 len) {
    return ((len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
}

static int range_overlap(u64 s1, u64 e1, u64 s2, u64 e2) {
    return (s1 < e2 && s2 < e1);
}

/**
 * Walks the 4-level page table for `ctx` at virtual address `va`.  If
 * `alloc==1`, allocates intermediate page-table pages as needed.
 * Returns a pointer to the PTE for `va`, or NULL on failure.
 */
static inline u64 *get_pte_ptr(struct exec_context *ctx, u64 va, int alloc)
{
    u64 *table;
    u64 entry;
    u32 new_pfn;
    u64 idx;

    /* Level-1 (PGD) */
    table = (u64*)osmap(ctx->pgd);
    if (!table) return NULL;
    idx   = va_to_index(va, PGD_SHIFT);
    entry = table[idx];
    if (!(entry & PTE_P)) {
        if (!alloc) return NULL;
        if (!(new_pfn = os_pfn_alloc(OS_PT_REG))) return NULL;
        u64 *new_tbl = (u64*)osmap(new_pfn);
        for (int i = 0; i < PTRS_PER_PT; i++) new_tbl[i] = 0;
        table[idx] = ((u64)new_pfn << PTE_SHIFT) | PTE_P | PTE_W | PTE_U;
        table = new_tbl;
    } else {
        table = (u64*)osmap(entry >> PTE_SHIFT);
    }

    /* Level-2 (PUD) */
    idx   = va_to_index(va, PUD_SHIFT);
    entry = table[idx];
    if (!(entry & PTE_P)) {
        if (!alloc) return NULL;
        if (!(new_pfn = os_pfn_alloc(OS_PT_REG))) return NULL;
        u64 *new_tbl = (u64*)osmap(new_pfn);
        for (int i = 0; i < PTRS_PER_PT; i++) new_tbl[i] = 0;
        table[idx] = ((u64)new_pfn << PTE_SHIFT) | PTE_P | PTE_W | PTE_U;
        table = new_tbl;
    } else {
        table = (u64*)osmap(entry >> PTE_SHIFT);
    }

    /* Level-3 (PMD) */
    idx   = va_to_index(va, PMD_SHIFT);
    entry = table[idx];
    if (!(entry & PTE_P)) {
        if (!alloc) return NULL;
        if (!(new_pfn = os_pfn_alloc(OS_PT_REG))) return NULL;
        u64 *new_tbl = (u64*)osmap(new_pfn);
        for (int i = 0; i < PTRS_PER_PT; i++) new_tbl[i] = 0;
        table[idx] = ((u64)new_pfn << PTE_SHIFT) | PTE_P | PTE_W | PTE_U;
        table = new_tbl;
    } else {
        table = (u64*)osmap(entry >> PTE_SHIFT);
    }

    /* Level-4 (PTE) */
    idx = va_to_index(va, PTE_SHIFT);
    return &table[idx];
}

/**
 * Part 1 + Part 2: Change protection in VMAs *and* enforce it in the page table.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (length <= 0) return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE))
        return -EINVAL;

    u64 len   = align_length(length);
    u64 start = addr;
    u64 end   = addr + len;
    struct vm_area *head = current->vm_area, *prev = head, *iter = head->vm_next;

    /* 1) VMA-list splitting/merging (same as Part 1) */
    while (iter) {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end)) {
            prev = iter;
            iter = iter->vm_next;
            continue;
        }
        u64 ov_s = start > iter->vm_start ? start : iter->vm_start;
        u64 ov_e = end   < iter->vm_end   ? end   : iter->vm_end;

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end) {
            iter->access_flags = prot;
            prev = iter;
            iter = iter->vm_next;
        }
        else if (ov_s <= iter->vm_start) {
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            post->vm_start = ov_e;
            post->vm_end   = iter->vm_end;
            post->access_flags = iter->access_flags;
            post->vm_next  = iter->vm_next;
            iter->vm_end   = ov_e;
            iter->access_flags = prot;
            iter->vm_next  = post;
            stats->num_vm_area++;
            prev = post;
            iter = post->vm_next;
        }
        else if (ov_e >= iter->vm_end) {
            struct vm_area *pre = os_alloc(sizeof(*pre));
            if (!pre) return -ENOMEM;
            pre->vm_start      = iter->vm_start;
            pre->vm_end        = ov_s;
            pre->access_flags  = iter->access_flags;
            pre->vm_next       = iter->vm_next;
            iter->vm_start     = ov_s;
            iter->access_flags = prot;
            iter->vm_next      = pre;
            prev->vm_next      = iter;
            stats->num_vm_area++;
            prev = pre;
            iter = pre->vm_next;
        }
        else {
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            post->vm_start      = ov_e;
            post->vm_end        = iter->vm_end;
            post->access_flags  = iter->access_flags;
            post->vm_next       = iter->vm_next;

            struct vm_area *mid = os_alloc(sizeof(*mid));
            if (!mid) return -ENOMEM;
            mid->vm_start      = ov_s;
            mid->vm_end        = ov_e;
            mid->access_flags  = prot;
            mid->vm_next       = post;

            iter->vm_end       = ov_s;
            iter->vm_next      = mid;
            stats->num_vm_area += 2;

            prev = post;
            iter = post->vm_next;
        }
    }

    /* 2) Enforce new permissions in any existing PTEs */
    for (u64 va = start; va < end; va += PAGE_SIZE) {
        u64 *pte = get_pte_ptr(current, va, 0);
        if (pte && (*pte & PTE_P)) {
            if (prot & PROT_WRITE) *pte |=  PTE_W;
            else                   *pte &= ~PTE_W;
        }
    }
    return 0;
}

/**
 * Part 1: mmap (unchanged)
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    struct vm_area *head = current->vm_area;
    if (!head) {
        struct vm_area *x = os_alloc(sizeof(*x));
        x->vm_start     = MMAP_AREA_START;
        x->vm_end       = MMAP_AREA_START + PAGE_SIZE;
        x->access_flags = 0;
        x->vm_next      = NULL;
        current->vm_area = x;
        stats->num_vm_area = 1;
    }

    u64 length_aligned = align_length(length);
    int use_fixed = (flags & MAP_FIXED) != 0;
    struct vm_area *prev, *iter;
    u64 start = 0;

    if (length <= 0 || length > (2 << 20))
        return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE))
        return -EINVAL;
    if (use_fixed && addr == 0)
        return -EINVAL;

    /* MAP_FIXED */
    if (use_fixed) {
        u64 end = addr + length_aligned;
        if (addr < MMAP_AREA_START || end > MMAP_AREA_END)
            return -EINVAL;
        for (iter = current->vm_area->vm_next; iter; iter = iter->vm_next)
            if (range_overlap(addr, end, iter->vm_start, iter->vm_end))
                return -EINVAL;
        start = addr;
        goto create;
    }

    /* Hint */
    if (addr) {
        u64 hint_start = addr;
        u64 hint_end   = addr + length_aligned;
        if (hint_start >= MMAP_AREA_START && hint_end <= MMAP_AREA_END) {
            int ok = 1;
            for (iter = current->vm_area->vm_next; iter; iter = iter->vm_next)
                if (range_overlap(hint_start, hint_end, iter->vm_start, iter->vm_end)) {
                    ok = 0; break;
                }
            if (ok) { start = hint_start; goto create; }
        }
    }

    /* First-fit in hole */
    prev = current->vm_area;
    for (iter = prev->vm_next; iter; prev = iter, iter = iter->vm_next) {
        u64 hole_start = prev->vm_end < MMAP_AREA_START ? MMAP_AREA_START : prev->vm_end;
        u64 hole_end   = iter->vm_start > MMAP_AREA_END ? MMAP_AREA_END : iter->vm_start;
        if (hole_end - hole_start >= length_aligned) {
            start = hole_start;
            goto create;
        }
    }
    /* After last VMA */
    {
        u64 hole_start = prev->vm_end < MMAP_AREA_START ? MMAP_AREA_START : prev->vm_end;
        if (MMAP_AREA_END - hole_start >= length_aligned) {
            start = hole_start;
            goto create;
        }
    }
    return -ENOMEM;

create:
    /* Insert new VMA */
    prev = current->vm_area;
    while (prev->vm_next && prev->vm_next->vm_start < start)
        prev = prev->vm_next;

    struct vm_area *vm = os_alloc(sizeof(*vm));
    if (!vm) return -ENOMEM;
    vm->vm_start     = start;
    vm->vm_end       = start + length_aligned;
    vm->access_flags = prot;
    vm->vm_next      = prev->vm_next;
    prev->vm_next    = vm;
    stats->num_vm_area++;

    /* Merge with next */
    if (vm->vm_next && vm->vm_end == vm->vm_next->vm_start
        && vm->access_flags == vm->vm_next->access_flags) {
        struct vm_area *n = vm->vm_next;
        vm->vm_end  = n->vm_end;
        vm->vm_next = n->vm_next;
        os_free(n, sizeof(*n));
        stats->num_vm_area--;
    }
    /* Merge with prev */
    if (prev != current->vm_area
        && prev->vm_end == vm->vm_start
        && prev->access_flags == vm->access_flags) {
        prev->vm_end   = vm->vm_end;
        prev->vm_next  = vm->vm_next;
        os_free(vm, sizeof(*vm));
        stats->num_vm_area--;
        start = prev->vm_start;
    }
    return (long)start;
}

/**
 * Part 1 + Part 2: munmap + free any allocated pages  
 */
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (length <= 0) return -EINVAL;
    u64 len   = align_length(length);
    u64 start = addr;
    u64 end   = addr + len;
    struct vm_area *head = current->vm_area, *prev = head, *iter = head->vm_next;

    /* 1) VMA-split/remove (Part 1 logic) */
    while (iter) {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end)) {
            prev = iter;
            iter = iter->vm_next;
            continue;
        }
        u64 ov_s = start > iter->vm_start ? start : iter->vm_start;
        u64 ov_e = end   < iter->vm_end   ? end   : iter->vm_end;

        /* fully covered */
        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end) {
            prev->vm_next = iter->vm_next;
            os_free(iter, sizeof(*iter));
            stats->num_vm_area--;
            iter = prev->vm_next;
        }
        /* overlap at beginning */
        else if (ov_s <= iter->vm_start) {
            iter->vm_start = ov_e;
            prev = iter;
            iter = iter->vm_next;
        }
        /* overlap at end */
        else if (ov_e >= iter->vm_end) {
            iter->vm_end = ov_s;
            prev = iter;
            iter = iter->vm_next;
        }
        /* split interior */
        else {
            struct vm_area *new_vma = os_alloc(sizeof(*new_vma));
            if (!new_vma) return -ENOMEM;
            new_vma->vm_start     = ov_e;
            new_vma->vm_end       = iter->vm_end;
            new_vma->access_flags = iter->access_flags;
            new_vma->vm_next      = iter->vm_next;
            iter->vm_end          = ov_s;
            iter->vm_next         = new_vma;
            stats->num_vm_area++;
            prev = new_vma;
            iter = new_vma->vm_next;
        }
    }

    /* 2) Tear down any page-table mappings */
    for (u64 va = start; va < end; va += PAGE_SIZE) {
        u64 *pte = get_pte_ptr(current, va, 0);
        if (pte && (*pte & PTE_P)) {
            u32 pfn = *pte >> PTE_SHIFT;
            os_pfn_free(USER_REG, pfn);
            *pte = 0;
        }
    }
    return 0;
}

/**
 * Part 2: lazy-allocation page-fault handler  
 */
long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    /* 1) Find corresponding VMA */
    struct vm_area *vma = current->vm_area->vm_next;
    while (vma && (addr < vma->vm_start || addr >= vma->vm_end))
        vma = vma->vm_next;
    if (!vma) return -1;

    int prot = vma->access_flags;

    /* 2) Copy-on-write protection fault? */
    if (error_code == ERR_CODE_PROT) {
        if (!(prot & PROT_WRITE))
            return -1;
        return handle_cow_fault(current, addr, prot);
    }

    /* 3) Read/write to unmapped page */
    if (error_code == ERR_CODE_READ || error_code == ERR_CODE_WRITE) {
        if (error_code == ERR_CODE_WRITE && !(prot & PROT_WRITE))
            return -1;

        u64 *pte = get_pte_ptr(current, addr, 1);
        if (!pte) return -1;

        if (!(*pte & PTE_P)) {
            u32 pfn = os_pfn_alloc(USER_REG);
            if (!pfn) return -1;
            /* zero the page */
            u64 *page = (u64*)osmap(pfn);
            for (int i = 0; i < PAGE_SIZE/sizeof(u64); i++)
                page[i] = 0;
            /* install PTE */
            u64 entry = ((u64)pfn << PTE_SHIFT) | PTE_P | PTE_U;
            if (prot & PROT_WRITE) entry |= PTE_W;
            *pte = entry;
        }
        return 1;
    }

    return -1;
}

/**
 * Part 3 stubs (unmodified)
 */
long do_cfork()
{
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    /* INSERT Part-3 code here */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    /* INSERT Part-3 CoW logic here */
    return -1;
}
