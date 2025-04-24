/* ------------------------------------------------------------------------- */
/* Paging constants & helpers (no <string.h> needed)                        */
#define PAGE_SHIFT   12                  /* 4 KB pages */
#define PAGE_SIZE    (1ULL << PAGE_SHIFT)
#define PTRS_PER_PT  512ULL

#define PGD_SHIFT    39
#define PUD_SHIFT    30
#define PMD_SHIFT    21
#define PTE_SHIFT    12

#define PGD_INDEX(x) (((x) >> PGD_SHIFT) & (PTRS_PER_PT - 1))
#define PUD_INDEX(x) (((x) >> PUD_SHIFT) & (PTRS_PER_PT - 1))
#define PMD_INDEX(x) (((x) >> PMD_SHIFT) & (PTRS_PER_PT - 1))
#define PTE_INDEX(x) (((x) >> PTE_SHIFT) & (PTRS_PER_PT - 1))

#ifndef OS_PT_REG
#define OS_PT_REG    0    /* region for page-table pages */
#endif
#ifndef USER_REG
#define USER_REG     1    /* region for user data pages */
#endif

#define PTE_PRESENT  (1ULL << 0)
#define PTE_RW       (1ULL << 1)
#define PTE_USER     (1ULL << 2)

/* Round up to next page multiple */
static u64 align_length(u64 len) {
    return ((len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
}
/* simple overlap test */
static int range_overlap(u64 s1, u64 e1, u64 s2, u64 e2) {
    return (s1 < e2 && s2 < e1);
}
/* ------------------------------------------------------------------------- */

/**
 * Part 2.1: page‐fault handler for lazy allocation in mmap’d VMAs.
 */
long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    /* 1) Find the covering VMA */
    u64 fault_va = addr & ~(PAGE_SIZE-1);
    struct vm_area *vma = current->vm_area->vm_next;
    while (vma && (fault_va < vma->vm_start || fault_va >= vma->vm_end))
        vma = vma->vm_next;
    if (!vma) 
        return -1;                /* no VMA ⇒ invalid access */

    /* 2) Decode fault type */
    int write_fault   = (error_code == ERR_CODE_WRITE || error_code == ERR_CODE_PROT);
    int protection_fault = (error_code == ERR_CODE_PROT);

    /* 2a) COW break? */
    if (protection_fault && write_fault) {
        if (!(vma->access_flags & PROT_WRITE))
            return -1;            /* really read-only ⇒ segfault */
        return handle_cow_fault(current, fault_va, vma->access_flags);
    }
    /* 2b) Not-present fault ⇒ lazy allocate */
    if (error_code == ERR_CODE_READ || error_code == ERR_CODE_WRITE) {
        if (write_fault && !(vma->access_flags & PROT_WRITE))
            return -1;            /* write into R-only VMA ⇒ invalid */

        /* alloc a new user page */
        u32 new_pfn = os_pfn_alloc(USER_REG);
        if (!new_pfn) return -ENOMEM;

        /* zero it manually */
        {
            char *page = (char*)osmap(new_pfn);
            for (u64 i = 0; i < PAGE_SIZE; i++)
                page[i] = 0;
        }

        /* walk/create 4-level table */
        u64 *pgd = (u64*)osmap(current->pgd);
        u64 *table = pgd;
        for (int level = 0; level < 4; level++) {
            int shift = (level==0?PGD_SHIFT:level==1?PUD_SHIFT:
                         level==2?PMD_SHIFT:PTE_SHIFT);
            u64 idx = (fault_va >> shift) & (PTRS_PER_PT - 1);
            u64 ent = table[idx];

            if (level < 3) {
                /* ensure next-level exists */
                if (!(ent & PTE_PRESENT)) {
                    u32 pfn = os_pfn_alloc(OS_PT_REG);
                    if (!pfn) return -ENOMEM;
                    /* clear new PT page */
                    {
                        char *pt = (char*)osmap(pfn);
                        for (u64 i=0;i<PAGE_SIZE;i++) pt[i]=0;
                    }
                    table[idx] = (pfn << PAGE_SHIFT)
                                | PTE_PRESENT|PTE_RW|PTE_USER;
                }
                /* descend */
                table = (u64*)osmap((table[idx] >> PAGE_SHIFT));
            } else {
                /* leaf: map our new frame */
                u64 flags = PTE_PRESENT|PTE_USER
                          | ((vma->access_flags & PROT_WRITE)?PTE_RW:0);
                table[idx] = (new_pfn << PAGE_SHIFT) | flags;
            }
        }
        return 1;  /* success */
    }

    /* all other cases invalid */
    return -1;
}

/**
 * Part 2.2: munmap must also free any already-mapped PFNs in [addr,addr+len).
 */
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (length <= 0) return -EINVAL;
    u64 len   = align_length(length);
    u64 start = addr, end = addr + len;

    /* free any already mapped pages */
    u64 *pgd_tbl = (u64*)osmap(current->pgd);
    for (u64 va = start; va < end; va += PAGE_SIZE) {
        u64 ent;
        u64 *pud, *pmd, *pte;

        /* PGD */
        ent = pgd_tbl[PGD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pud = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PUD */
        ent = pud[PUD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pmd = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PMD */
        ent = pmd[PMD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pte = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PTE */
        ent = pte[PTE_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;

        /* free frame and clear entry */
        os_pfn_free(USER_REG, (u32)(ent >> PAGE_SHIFT));
        pte[PTE_INDEX(va)] = 0;
    }

    /* now trim/split/remove VMAs exactly as before */
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;
    while (iter) {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end)) {
            prev = iter; iter = iter->vm_next;
            continue;
        }
        u64 ov_s = (start > iter->vm_start?start:iter->vm_start);
        u64 ov_e = (end   < iter->vm_end  ?end  :iter->vm_end);

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end) {
            /* fully covered */
            prev->vm_next = iter->vm_next;
            os_free(iter, sizeof(*iter));
            stats->num_vm_area--;
            iter = prev->vm_next;
        }
        else if (ov_s <= iter->vm_start) {
            /* trim front */
            iter->vm_start = ov_e;
            prev = iter; iter = iter->vm_next;
        }
        else if (ov_e >= iter->vm_end) {
            /* trim back */
            iter->vm_end = ov_s;
            prev = iter; iter = iter->vm_next;
        }
        else {
            /* split interior */
            struct vm_area *new_vma = os_alloc(sizeof(*new_vma));
            if (!new_vma) return -ENOMEM;
            new_vma->vm_start     = ov_e;
            new_vma->vm_end       = iter->vm_end;
            new_vma->access_flags = iter->access_flags;
            new_vma->vm_next      = iter->vm_next;
            iter->vm_end          = ov_s;
            iter->vm_next         = new_vma;
            stats->num_vm_area++;
            prev = new_vma; iter = new_vma->vm_next;
        }
    }
    return 0;
}

/**
 * Part 2.3: mprotect must also patch any already-mapped PTEs to new RW bits.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (length <= 0) return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE))
        return -EINVAL;
    u64 len   = align_length(length);
    u64 start = addr, end = addr + len;

    /* update any existing PTEs in that range */
    u64 *pgd_tbl = (u64*)osmap(current->pgd);
    for (u64 va = start; va < end; va += PAGE_SIZE) {
        u64 ent;
        u64 *pud, *pmd, *pte;

        ent = pgd_tbl[PGD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pud = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pud[PUD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pmd = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pmd[PMD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pte = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pte[PTE_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;

        /* rebuild leaf with new RW bit */
        u32 pfn = (u32)(ent >> PAGE_SHIFT);
        u64 flags = PTE_PRESENT|PTE_USER
                  | ((prot == (PROT_READ|PROT_WRITE))?PTE_RW:0);
        pte[PTE_INDEX(va)] = (pfn << PAGE_SHIFT) | flags;
    }

    /* then adjust VMAs exactly as your Part 1 mprotect did */
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;
    while (iter) {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end)) {
            prev = iter; iter = iter->vm_next;
            continue;
        }
        u64 ov_s = (start > iter->vm_start?start:iter->vm_start);
        u64 ov_e = (end   < iter->vm_end  ?end  :iter->vm_end);

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end) {
            /* fully covered: change flags */
            iter->access_flags = prot;
            prev = iter; iter = iter->vm_next;
        }
        else if (ov_s <= iter->vm_start) {
            /* split front */
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            post->vm_start     = ov_e;
            post->vm_end       = iter->vm_end;
            post->access_flags = iter->access_flags;
            post->vm_next      = iter->vm_next;
            iter->vm_end       = ov_e;
            iter->access_flags = prot;
            iter->vm_next      = post;
            stats->num_vm_area++;
            prev = post; iter = post->vm_next;
        }
        else if (ov_e >= iter->vm_end) {
            /* split back */
            struct vm_area *pre = os_alloc(sizeof(*pre));
            if (!pre) return -ENOMEM;
            pre->vm_start      = iter->vm_start;
            pre->vm_end        = ov_s;
            pre->access_flags  = iter->access_flags;
            pre->vm_next       = iter->vm_next;
            iter->vm_start     = ov_s;
            iter->access_flags = prot;
            iter->vm_next      = pre;
            stats->num_vm_area++;
            prev = pre; iter = pre->vm_next;
        }
        else {
            /* interior split */
            struct vm_area *mid  = os_alloc(sizeof(*mid));
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!mid || !post) return -ENOMEM;
            post->vm_start      = ov_e;
            post->vm_end        = iter->vm_end;
            post->access_flags  = iter->access_flags;
            post->vm_next       = iter->vm_next;
            mid->vm_start       = ov_s;
            mid->vm_end         = ov_e;
            mid->access_flags   = prot;
            mid->vm_next        = post;
            iter->vm_end        = ov_s;
            iter->vm_next       = mid;
            stats->num_vm_area += 2;
            prev = post; iter = post->vm_next;
        }
    }
    return 0;
}
