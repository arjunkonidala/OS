/* ----------------------------------------------------------------------------
 * PART2 – Page-Table Manipulations (Lazy alloc, munmap, mprotect)
 */

/* Reuse your existing macros… */
#define PAGE_SIZE    4096
#define PAGE_SHIFT   12
#define PGD_SHIFT    39
#define PUD_SHIFT    30
#define PMD_SHIFT    21
#define PTE_SHIFT    12
#define PTRS_PER_PT  512ULL

#define PGD_INDEX(x) (((x) >> PGD_SHIFT) & (PTRS_PER_PT - 1))
#define PUD_INDEX(x) (((x) >> PUD_SHIFT) & (PTRS_PER_PT - 1))
#define PMD_INDEX(x) (((x) >> PMD_SHIFT) & (PTRS_PER_PT - 1))
#define PTE_INDEX(x) (((x) >> PTE_SHIFT) & (PTRS_PER_PT - 1))

#define USER_REG   0   /* for user pages */
#define OS_PT_REG  1   /* for OS page-table pages */

/**
 * Part2.1 – Lazy‐allocate page-fault handler.
 */
long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    u64 fault_va = addr & ~(PAGE_SIZE-1);
    struct vm_area *vma;
    int is_write   = (error_code & 0x2) != 0;
    int is_present = (error_code & 0x1) != 0;

    /* 1) Find the VMA covering fault_va */
    for (vma = current->vm_area->vm_next; vma; vma = vma->vm_next) {
        if (fault_va >= vma->vm_start && fault_va < vma->vm_end)
            break;
    }
    if (!vma) return -1;  /* no VMA ⇒ invalid access */

    /* 2) Protection / COW fault? */
    if (is_present && is_write) {
        if (!(vma->access_flags & PROT_WRITE))
            return -1;  /* write to read‐only */
        return handle_cow_fault(current, fault_va, vma->access_flags);
    }

    /* 3) Lazy‐allocate on not‐present fault */
    if (!is_present) {
        if (is_write && !(vma->access_flags & PROT_WRITE))
            return -1;  /* write to R-only VMA ⇒ invalid */

        /* allocate one zeroed user page */
        u32 new_pfn = os_pfn_alloc(USER_REG);
        if (!new_pfn) return -ENOMEM;
        memset(osmap(new_pfn), 0, PAGE_SIZE);

        /* walk / build the 4-level page table */
        u64 *table = (u64*)osmap(current->pgd);
        for (int lvl = 0; lvl < 4; lvl++) {
            u64 idx = va_to_index(fault_va,
                         lvl==0?PGD_SHIFT:
                         lvl==1?PUD_SHIFT:
                         lvl==2?PMD_SHIFT:PTE_SHIFT);
            u64 ent = table[idx];

            if (lvl < 3) {
                /* ensure next-level table exists */
                if (!(ent & PTE_P)) {
                    u32 pfn = os_pfn_alloc(OS_PT_REG);
                    if (!pfn) {
                        os_pfn_free(USER_REG, new_pfn);
                        return -ENOMEM;
                    }
                    memset(osmap(pfn), 0, PAGE_SIZE);
                    table[idx] = (pfn<<PAGE_SHIFT) | PTE_P | PTE_W | PTE_U;
                }
                table = (u64*)osmap(table[idx] >> PAGE_SHIFT);
            } else {
                /* install the leaf PTE with VMA’s prot */
                u64 flags = PTE_P | PTE_U |
                            ((vma->access_flags & PROT_WRITE) ? PTE_W : 0);
                table[idx] = (new_pfn<<PAGE_SHIFT) | flags;
            }
        }
        return 1;  /* handled */
    }

    return -1;  /* everything else is invalid */
}

/**
 * Part2.2 – munmap with page freeing.
 */
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (length <= 0) return -EINVAL;
    u64 len   = align_length(length);
    u64 start = addr, end = addr + len;

    /* 0) Free any mapped PFNs in [start,end) */
    u64 *pgd_tbl = (u64*)osmap(current->pgd);
    for (u64 va = start; va < end; va += PAGE_SIZE) {
        u64 ent;
        u64 *pud, *pmd, *pte;

        /* PGD */
        ent = pgd_tbl[PGD_INDEX(va)];
        if (!(ent & PTE_P)) continue;
        pud = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PUD */
        ent = pud[PUD_INDEX(va)];
        if (!(ent & PTE_P)) continue;
        pmd = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PMD */
        ent = pmd[PMD_INDEX(va)];
        if (!(ent & PTE_P)) continue;
        pte = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PTE */
        ent = pte[PTE_INDEX(va)];
        if (!(ent & PTE_P)) continue;
        os_pfn_free(USER_REG, (u32)(ent >> PAGE_SHIFT));
        pte[PTE_INDEX(va)] = 0;
    }

    /* 1) Now trim/split/remove VMAs exactly as in Part-1 unmap */
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;
    while (iter) {
        if (!range_overlap(start,end, iter->vm_start, iter->vm_end)) {
            prev = iter; iter = iter->vm_next;
            continue;
        }
        u64 ov_s = start > iter->vm_start ? start : iter->vm_start;
        u64 ov_e = end   < iter->vm_end   ? end   : iter->vm_end;

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end) {
            /* fully covered */
            prev->vm_next = iter->vm_next;
            os_free(iter, sizeof(*iter));
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
            /* interior split */
            struct vm_area *new_vma = os_alloc(sizeof(*new_vma));
            if (!new_vma) return -ENOMEM;
            new_vma->vm_start     = ov_e;
            new_vma->vm_end       = iter->vm_end;
            new_vma->access_flags = iter->access_flags;
            new_vma->vm_next      = iter->vm_next;
            iter->vm_end          = ov_s;
            iter->vm_next         = new_vma;
            prev = new_vma; iter = new_vma->vm_next;
        }
    }
    return 0;
}

/**
 * Part2.3 – mprotect with PTE updates.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (length <= 0) return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE))
        return -EINVAL;
    u64 len   = align_length(length);
    u64 start = addr, end = addr + len;

    /* 0) Walk all pages in [start,end) and update leaf PTE RW bit */
    u64 *pgd_tbl = (u64*)osmap(current->pgd);
    for (u64 va = start; va < end; va += PAGE_SIZE) {
        u64 ent;
        u64 *pud, *pmd, *pte;

        /* PGD */
        ent = pgd_tbl[PGD_INDEX(va)];
        if (!(ent & PTE_P)) continue;
        pud = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PUD */
        ent = pud[PUD_INDEX(va)];
        if (!(ent & PTE_P)) continue;
        pmd = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PMD */
        ent = pmd[PMD_INDEX(va)];
        if (!(ent & PTE_P)) continue;
        pte = (u64*)osmap(ent >> PAGE_SHIFT);

        /* PTE */
        ent = pte[PTE_INDEX(va)];
        if (!(ent & PTE_P)) continue;
        u32 pfn = (u32)(ent >> PAGE_SHIFT);
        u64 flags = PTE_P | PTE_U
                  | ((prot == (PROT_READ|PROT_WRITE)) ? PTE_W : 0);
        pte[PTE_INDEX(va)] = (pfn<<PAGE_SHIFT) | flags;
    }

    /* 1) Adjust VMA list exactly as in your Part-1 mprotect */
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;
    while (iter) {
        if (!range_overlap(start,end, iter->vm_start, iter->vm_end)) {
            prev = iter; iter = iter->vm_next;
            continue;
        }
        u64 ov_s = start > iter->vm_start ? start : iter->vm_start;
        u64 ov_e = end   < iter->vm_end   ? end   : iter->vm_end;

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end) {
            iter->access_flags = prot;
            prev = iter; iter = iter->vm_next;
        }
        else if (ov_s <= iter->vm_start) {
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            post->vm_start     = ov_e;
            post->vm_end       = iter->vm_end;
            post->access_flags = iter->access_flags;
            post->vm_next      = iter->vm_next;
            iter->vm_end       = ov_e;
            iter->access_flags = prot;
            iter->vm_next      = post;
            prev = post; iter = post->vm_next;
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
            prev = pre; iter = pre->vm_next;
        }
        else {
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
            prev = post; iter = post->vm_next;
        }
    }
    return 0;
}
