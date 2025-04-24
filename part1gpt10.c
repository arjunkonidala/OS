long vm_area_map(struct exec_context *current,
                 u64 addr, int length, int prot, int flags)
{
    struct vm_area *dummy = current->vm_area, *prev, *iter;
    u64 length_aligned, start = 0;
    int is_fixed = (flags & MAP_FIXED) != 0;
    int placed   = 0;

    /* 1) validate args */
    if (length <= 0)                    return -EINVAL;
    length_aligned = page_round_up(length);
    if (length_aligned > (MMAP_AREA_END - (MMAP_AREA_START + PAGE_SIZE)))
                                        return -EINVAL;
    if (prot != PROT_READ &&
        prot != (PROT_READ|PROT_WRITE))
                                        return -EINVAL;

    /*
     * 2) MAP_FIXED: must be page-aligned and wholly free
     */
    if (is_fixed) {
        if (addr & (PAGE_SIZE-1))       return -EINVAL;
        u64 end = addr + length_aligned;
        if (addr < MMAP_AREA_START + PAGE_SIZE ||
            end  > MMAP_AREA_END)
            return -EINVAL;
        for (iter = dummy->vm_next; iter; iter = iter->vm_next) {
            if (range_overlap(addr, end,
                              iter->vm_start, iter->vm_end))
                return -ENOMEM;
        }
        start  = addr;
        placed = 1;
    }

    /*
     * 3) Hint (non-fixed): try the page-rounded hint
     */
    if (!placed && addr) {
        u64 hint = page_round_up(addr);
        u64 end  = hint + length_aligned;
        if (hint >= MMAP_AREA_START + PAGE_SIZE &&
            end  <= MMAP_AREA_END) {
            int ok = 1;
            for (iter = dummy->vm_next; iter; iter = iter->vm_next) {
                if (range_overlap(hint, end,
                                  iter->vm_start, iter->vm_end)) {
                    ok = 0;
                    break;
                }
            }
            if (ok) {
                start  = hint;
                placed = 1;
            }
        }
    }

    /*
     * 4) First-fit into the first hole
     *    (we always reserve one page after MMAP_AREA_START for the dummy)
     */
    if (!placed) {
        prev = dummy;
        for (iter = dummy->vm_next; iter; prev = iter, iter = iter->vm_next) {
            u64 hole_start = (prev == dummy
                              ? MMAP_AREA_START + PAGE_SIZE
                              : prev->vm_end);
            u64 hole_end   = iter->vm_start;
            if (hole_end - hole_start >= length_aligned) {
                start  = hole_start;
                placed = 1;
                break;
            }
        }
        if (!placed) {
            /* after the last VMA */
            u64 hole_start = (prev == dummy
                              ? MMAP_AREA_START + PAGE_SIZE
                              : prev->vm_end);
            if (MMAP_AREA_END - hole_start >= length_aligned) {
                start  = hole_start;
                placed = 1;
            }
        }
    }
    if (!placed)
        return -ENOMEM;

    /*
     * 5) Insert new VMA at 'start'
     */
    prev = dummy;
    while (prev->vm_next && prev->vm_next->vm_start < start)
        prev = prev->vm_next;

    struct vm_area *vm = os_alloc(sizeof(*vm));
    if (!vm) return -ENOMEM;
    vm->vm_start     = start;
    vm->vm_end       = start + length_aligned;
    vm->access_flags = prot;
    vm->vm_next      = prev->vm_next;
    prev->vm_next    = vm;

    /* 6) Merge with next if same prot */
    if (vm->vm_next &&
        vm->vm_end == vm->vm_next->vm_start &&
        vm->access_flags == vm->vm_next->access_flags) {
        struct vm_area *n = vm->vm_next;
        vm->vm_end   = n->vm_end;
        vm->vm_next  = n->vm_next;
        os_free(n, sizeof(*n));
    }

    /* 7) Merge with prev if same prot */
    if (prev != dummy &&
        prev->vm_end == vm->vm_start &&
        prev->access_flags == vm->access_flags) {
        prev->vm_end  = vm->vm_end;
        prev->vm_next = vm->vm_next;
        os_free(vm, sizeof(*vm));
        start = prev->vm_start;
    }

    return (long)start;
}

/*
 * ----------------------------------------------------------------------------
 * Part 1.2: munmap()
 */
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (length <= 0) return -EINVAL;
    u64 len   = page_round_up(length);
    u64 start = addr, end = addr + len;

    /* 0) free any mapped pages in [start,end) */
    u64 *pgd_tbl = (u64*)osmap(current->pgd);
    for (u64 va = start; va < end; va += PAGE_SIZE) {
        /* four-level walk and os_pfn_free if PRESENT… */
    }

    /* 1) now remove/trim/split VMAs */
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;
    while (iter) {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end)) {
            prev = iter; iter = iter->vm_next;
            continue;
        }
        u64 ov_s = max(start, iter->vm_start);
        u64 ov_e = min(end,   iter->vm_end);

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
            iter->vm_end   = ov_s;
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

/*
 * ----------------------------------------------------------------------------
 * Part 1.3: mprotect()
 */
long vm_area_mprotect(struct exec_context *current,
                      u64 addr, int length, int prot)
{
    if (length <= 0) return -EINVAL;
    if (prot != PROT_READ &&
        prot != (PROT_READ|PROT_WRITE))
        return -EINVAL;

    u64 len   = page_round_up(length);
    u64 start = addr, end = addr + len;

    /* 0) update existing PTEs */
    u64 *pgd_tbl = (u64*)osmap(current->pgd);
    for (u64 va = start; va < end; va += PAGE_SIZE) {
        /* four-level walk and rebuild PTE with new RW bits… */
    }

    /* 1) adjust VMAs: update, trim, split as per spec */
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;
    while (iter) {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end)) {
            prev = iter; iter = iter->vm_next;
            continue;
        }
        u64 ov_s = max(start, iter->vm_start);
        u64 ov_e = min(end,   iter->vm_end);

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end) {
            /* fully covered */
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
            prev = post; iter = post->vm_next;
        }
    }
    return 0;
}
