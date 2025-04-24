/**************************************** PART1 ********************************************/
/** Part1 - 1st Function  ---  mmap system call implementation. ***/
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{   
    u64 start = 0;
    u64 length_aligned = align_length(length);
    struct vm_area *dummy = current->vm_area;
    struct vm_area *prev, *iter;
    int use_fixed = ((flags & MAP_FIXED) != 0);                                        // Checking whether flags and map_fixed are equal or not.
    int do_insert = 0;

    if (length <= 0 || length > (2 << 20)) return -EINVAL;                             /* Validate args */
    if (prot != PROT_READ && prot != (PROT_READ | PROT_WRITE)) return -EINVAL;
    if (use_fixed && addr == 0) return -EINVAL;
    if (use_fixed)                                                                     // 1) MAP_FIXED: exact region must be free
    {
        u64 end = addr + length_aligned;
        if (addr < MMAP_AREA_START || end > MMAP_AREA_END) return -EINVAL;
        for (iter = dummy->vm_next; iter; iter = iter->vm_next)
        {
            if (range_overlap(addr, end, iter->vm_start, iter->vm_end)) return -EINVAL;
        }
        start = addr;
        do_insert = 1;
    }
    if (!do_insert && addr)                                                            // 2) Hint address (non-fixed) 
    {
        u64 hint_start = addr, hint_end = addr + length_aligned;
        if (hint_start >= MMAP_AREA_START && hint_end <= MMAP_AREA_END)
        {
            int ok = 1;
            for (iter = dummy->vm_next; iter; iter = iter->vm_next)
            {
                if (range_overlap(hint_start, hint_end, iter->vm_start, iter->vm_end))
                {
                    ok = 0;
                    break;
                }
            }

            if (ok)
            {
                start = hint_start;
                do_insert = 1;
            }
        }
    }
    if (!do_insert)                                                                    // 3) Otherwise scan for the first hole
    {
        prev = dummy;
        for (iter = dummy->vm_next; iter; prev = iter, iter = iter->vm_next)
        {
            /* <-- here’s the only change: skip dummy’s 4 KB page */
            u64 hole_start = (prev == dummy)
                ? (dummy->vm_start + PAGE_SIZE)
                : prev->vm_end;
            u64 hole_end   = iter->vm_start;
            if (hole_end - hole_start >= length_aligned)
            {
                start = hole_start;
                do_insert = 1;
                break;
            }
        }

        if (!do_insert)                                                                // after the last VMA 
        {
            u64 hole_start = (prev == dummy)
                ? (dummy->vm_start + PAGE_SIZE)
                : prev->vm_end;
            if (MMAP_AREA_END - hole_start >= length_aligned)
            {
                start = hole_start;
                do_insert = 1;
            }
        }
    }
    if (!do_insert) return -ENOMEM;

    prev = dummy;                                                                       // === Now insert the new VMA === 
    while (prev->vm_next && prev->vm_next->vm_start < start) prev = prev->vm_next;
    struct vm_area *vm = os_alloc(sizeof(*vm));

    if (!vm) return -ENOMEM;
    
    vm->vm_start = start;
    vm->vm_end = start + length_aligned;
    vm->access_flags = prot;
    vm->vm_next = prev->vm_next;
    prev->vm_next = vm;

    if (vm->vm_next && vm->vm_end == vm->vm_next->vm_start && vm->access_flags == vm->vm_next->access_flags)                // Merge with next, if same prot
    {
        struct vm_area *n = vm->vm_next;
        vm->vm_end = n->vm_end;
        vm->vm_next = n->vm_next;
        os_free(n, sizeof(*n));
    }

    if (prev != dummy && prev->vm_end == vm->vm_start && prev->access_flags == vm->access_flags)                            // Merge with prev, if same prot
    {
        prev->vm_end = vm->vm_end;
        prev->vm_next = vm->vm_next;
        os_free(vm, sizeof(*vm));
        start = prev->vm_start;
    }
    return (long)start;
}

/** Part1 - 2nd Function --- munmap system call implementation ***/
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (length <= 0) return -EINVAL;
    u64 len   = align_length(length);
    u64 start = addr;
    u64 end   = addr + len;
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;
 
    while (iter)
    {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end))
        {
            prev = iter;
            iter = iter->vm_next;
            continue;
        }

        u64 ov_s = start > iter->vm_start ? start : iter->vm_start;
        u64 ov_e = end < iter->vm_end ? end : iter->vm_end;
        
        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end)                     // Fully covered 
        {
            prev->vm_next = iter->vm_next;
            os_free(iter, sizeof(*iter));
            iter = prev->vm_next;
        }
        
        else if (ov_s <= iter->vm_start)                                        // Overlap at beginning
        {
            iter->vm_start = ov_e;
            prev = iter;
            iter = iter->vm_next;
        }
        
        else if (ov_e >= iter->vm_end)                                          // Overlap at end
        {
            iter->vm_end = ov_s;
            prev = iter;
            iter = iter->vm_next;
        }
        
        else                                                                    // Split interior
        {
            struct vm_area *new_vma = os_alloc(sizeof(*new_vma));
            if (!new_vma) return -ENOMEM;
            new_vma->vm_start = ov_e;
            new_vma->vm_end = iter->vm_end;
            new_vma->access_flags = iter->access_flags;
            new_vma->vm_next = iter->vm_next;
            iter->vm_end = ov_s;
            iter->vm_next = new_vma;
            prev = new_vma;
            iter = new_vma->vm_next;
        }
    }
    return 0;
}

/** Part1 - 3rd Function --- mprotect System call implementation ***/
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (length <= 0) return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ | PROT_WRITE)) return -EINVAL;

    u64 len   = align_length(length);
    u64 start = addr;
    u64 end   = addr + len;
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;

    while (iter)
    {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end))
        {
            prev = iter;
            iter = iter->vm_next;
            continue;
        }

        u64 ov_s = start > iter->vm_start ? start : iter->vm_start;
        u64 ov_e = end < iter->vm_end ? end : iter->vm_end;

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end)                             // Fully covered: change flags
        {
            iter->access_flags = prot;
            prev = iter;
            iter = iter->vm_next;
        }

        else if (ov_s <= iter->vm_start)                                                // Overlap at beginning
        {
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            
            post->vm_start = ov_e;
            post->vm_end = iter->vm_end;
            post->access_flags = iter->access_flags;
            post->vm_next = iter->vm_next;
            iter->vm_end = ov_e;
            iter->access_flags = prot;
            iter->vm_next = post;
            prev = post;
            iter = post->vm_next;
        }

        else if (ov_e >= iter->vm_end)                                                  // Overlap at end
        {
            struct vm_area *pre = os_alloc(sizeof(*pre));
            if (!pre) return -ENOMEM;
            
            pre->vm_start = iter->vm_start;
            pre->vm_end = ov_s;
            pre->access_flags = iter->access_flags;
            pre->vm_next = iter->vm_next;
            iter->vm_start = ov_s;
            iter->access_flags = prot;
            iter->vm_next = pre;
            prev->vm_next = iter;
            prev = pre;
            iter = pre->vm_next;
        }

        else                                                                            // Interior split
        {
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;

            post->vm_start = ov_e;
            post->vm_end = iter->vm_end;
            post->access_flags = iter->access_flags;
            post->vm_next = iter->vm_next;

            struct vm_area *mid = os_alloc(sizeof(*mid));
            if (!mid) return -ENOMEM;

            mid->vm_start = ov_s;
            mid->vm_end = ov_e;
            mid->access_flags = prot;
            mid->vm_next = post;
            u64 orig_start = iter->vm_start;
            iter->vm_start = orig_start;
            iter->vm_end = ov_s;
            iter->vm_next = mid;
            prev = post;
            iter = post->vm_next;
        }
    }
    return 0;
}
