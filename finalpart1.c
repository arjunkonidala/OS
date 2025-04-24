// 


#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */

#define PAGE_SIZE    4096                  
#define PGD_SHIFT    39
#define PUD_SHIFT    30
#define PMD_SHIFT    21
#define PTE_SHIFT    12
#define PTRS_PER_PT  512ULL

#define PAGE_SHIFT    12    /* number of bits to shift to get page offset */
#define USER_REG      0            /* region index for user pages */
#define OS_PT_REG     1            /* region index for OS page‐table pages */


/* Page‑fault error codes from assignment */
#define ERR_CODE_READ    0x4
#define ERR_CODE_WRITE   0x6
#define ERR_CODE_PROT    0x7

/* PTE flag bits (as in gemOS/page.h) */
#define PTE_P   (1ULL << 0)
#define PTE_W   (1ULL << 1)
#define PTE_U   (1ULL << 2)


static u64 pgsizecalc(u64 len) 
{
    return ((len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
}
 

static int range_overlap(u64 s1, u64 e1, u64 s2, u64 e2)
{
    return (s1 < e2 && s2 < e1);
}

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot) 
{
    if (length <= 0) return -EINVAL;

    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE)) return -EINVAL;

    u64 len = pgsizecalc(length);
    u64 start = addr;
    u64 end = addr + len;
    
    struct vm_area *head = current->vm_area, *prev = head, *d1 = head->vm_next;

    while (d1)
    {
        if (!range_overlap(start, end, d1->vm_start, d1->vm_end)) {
            prev = d1;
            d1 = d1->vm_next;
            continue;
        }

        u64 ov_s;
        if(start > d1->vm_start){
            ov_s=start;
        }
        else{
            ov_s=d1->vm_start;
        }
        u64 ov_e ;
        if(end<d1->vm_end){
            ov_e=end;
        }
        else{
            ov_e=d1->vm_end;
        }
        /* Fully covered: change flags */

        if (ov_s <= d1->vm_start && ov_e >= d1->vm_end) 
        {
            d1->access_flags = prot;
            prev = d1;
            d1 = d1->vm_next;
        }

        /* Overlap at beginning */
        else if (ov_s <= d1->vm_start) 
        {
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            post->vm_start = ov_e;
            post->vm_end = d1->vm_end;
            post->access_flags = d1->access_flags;
            post->vm_next = d1->vm_next;
            d1->vm_end = ov_e;
            d1->access_flags = prot;
            d1->vm_next = post;
            stats->num_vm_area++;
            prev = post;
            d1 = post->vm_next;
        }

        /* Overlap at end */
        else if (ov_e >= d1->vm_end) 
        {
            struct vm_area *pre = os_alloc(sizeof(*pre));
            if (!pre) return -ENOMEM;
            pre->vm_start = d1->vm_start;
            pre->vm_end = ov_s;
            pre->access_flags = d1->access_flags;
            pre->vm_next = d1->vm_next;
            d1->vm_start = ov_s;
            d1->access_flags = prot;
            d1->vm_next = pre;
            prev->vm_next = d1;
            stats->num_vm_area++;
            prev = pre;
            d1 = pre->vm_next;
        }

        /* Interior split */
        else 
        {
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            post->vm_start = ov_e;
            post->vm_end = d1->vm_end;
            post->access_flags = d1->access_flags;
            post->vm_next = d1->vm_next;

            struct vm_area *mid = os_alloc(sizeof(*mid));
            if (!mid) return -ENOMEM;
            mid->vm_start = ov_s;
            mid->vm_end = ov_e;
            mid->access_flags = prot;
            mid->vm_next = post;

            u64 orig_start = d1->vm_start;
            d1->vm_start = orig_start;
            d1->vm_end = ov_s;
            d1->vm_next = mid;
            stats->num_vm_area += 2;

            prev = post;
            d1 = post->vm_next;
        }
    }
    return 0;
}











/**
 * mmap system call implementation.
 */
// long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
// {
//     return -EINVAL;
// }
//add a dummy node
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    struct vm_area *head = current->vm_area;
    if(head==0){
        
        
        struct vm_area* x=os_alloc(sizeof(struct vm_area));
        x->vm_start=MMAP_AREA_START;
        x->vm_end=MMAP_AREA_START+4096;
        x->vm_next=head;
        x->access_flags=0x0;
        head=x;
        current->vm_area = x;
        stats->num_vm_area = 1;
        
    }

    struct vm_area *prev, *d1;
    u64 length_aligned = pgsizecalc(length);
    u64 start = 0;
    int use_fixed = (flags & MAP_FIXED) != 0;

    /* Validate args */
    if (length <= 0 || length > (2 << 20)) return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE)) return -EINVAL;
    if (use_fixed && addr == 0) return -EINVAL;

    /* MAP_FIXED: exact region must be free */
    if (use_fixed) 
    {
        u64 end = addr + length_aligned;
        if (addr < MMAP_AREA_START || end > MMAP_AREA_END) return -EINVAL;
        for (d1 = head->vm_next; d1; d1 = d1->vm_next) 
        {
            if (range_overlap(addr, end, d1->vm_start, d1->vm_end)) return -EINVAL;
        }
        start = addr;
        goto create;
    }

    /* Hint: try addr if within limits and free */
    if (addr) 
    {
        u64 hint_start = addr;
        u64 hint_end = addr + length_aligned;
        if (hint_start >= MMAP_AREA_START && hint_end <= MMAP_AREA_END)
        {
            int ok = 1;
            for (d1 = head->vm_next; d1; d1 = d1->vm_next) 
            {
                if (range_overlap(hint_start, hint_end, d1->vm_start, d1->vm_end)) { ok = 0; break; }
            }
            if (ok) { start = hint_start; goto create; }
        }
    }

    /* Find first hole */
    prev = head;
    for (d1 = head->vm_next; d1; prev = d1, d1 = d1->vm_next) 
    {
        u64 hole_start;
        if (prev->vm_end < MMAP_AREA_START )
        {
            hole_start = MMAP_AREA_START;
        }
        else hole_start = prev->vm_end;


        // u64 hole_end = d1->vm_start > MMAP_AREA_END ? MMAP_AREA_END : d1->vm_start;

        u64 hole_end;
        if (d1->vm_start > MMAP_AREA_END)
        {
            hole_end = MMAP_AREA_END;
        }
        else hole_end = d1->vm_start;


        if (hole_end - hole_start >= length_aligned) { start = hole_start; goto create; }
    }

    /* After last VMA */
    {   
        u64 hole_start;
        if (prev->vm_end < MMAP_AREA_START)
        {
            hole_start = MMAP_AREA_START;
        }
        else hole_start = prev->vm_end;

        // u64 hole_start = prev->vm_end < MMAP_AREA_START ? MMAP_AREA_START : prev->vm_end;

        if (MMAP_AREA_END - hole_start >= length_aligned) { start = hole_start; goto create; }
    }
    return -ENOMEM;

create:
    /* Insert new VMA */
    prev = head;
    while (prev->vm_next && prev->vm_next->vm_start < start) prev = prev->vm_next;
    struct vm_area *vm = os_alloc(sizeof(*vm));
    if (!vm) return -ENOMEM;
    vm->vm_start = start;
    vm->vm_end = start + length_aligned;
    vm->access_flags = prot;
    vm->vm_next = prev->vm_next;
    prev->vm_next = vm;
    stats->num_vm_area++;

    /* Merge with next */
    if (vm->vm_next && vm->vm_end == vm->vm_next->vm_start && vm->access_flags == vm->vm_next->access_flags) 
    {
        struct vm_area *n = vm->vm_next;
        vm->vm_end = n->vm_end;
        vm->vm_next = n->vm_next;
        os_free(n, sizeof(*n));
        stats->num_vm_area--;
    }
    /* Merge with prev */
    if (prev != head && prev->vm_end == vm->vm_start && prev->access_flags == vm->access_flags) 
    {
        prev->vm_end = vm->vm_end;
        prev->vm_next = vm->vm_next;
        os_free(vm, sizeof(*vm));
        stats->num_vm_area--;
        start = prev->vm_start;
    }
    return (long)start;
}














/**
 * munmap system call implemenations
 */

// long vm_area_unmap(struct exec_context *current, u64 addr, int length)
// {
//     return -EINVAL;
// }

long vm_area_unmap(struct exec_context *current, u64 addr, int length) 
{
    if (length <= 0) return -EINVAL;
    u64 len = pgsizecalc(length);
    u64 start = addr;
    u64 end = addr + len;
    struct vm_area *head = current->vm_area, *prev = head, *d1 = head->vm_next;

    while (d1) 
    {
        if (!range_overlap(start, end, d1->vm_start, d1->vm_end)) 
        {
            prev = d1;
            d1 = d1->vm_next;
            continue;
        }

        u64 ov_s;
        if (start > d1->vm_start)
        {
            ov_s = start;
        }
        else ov_s = d1->vm_start;

        // u64 ov_s = start > d1->vm_start ? start : d1->vm_start;

        // u64 ov_e = end < d1->vm_end ? end : d1->vm_end;

        u64 ov_e;
        if (end < d1->vm_end)
        {
            ov_e = end;
        }
        else ov_e = d1->vm_end;

        /* Fully covered */
        if (ov_s <= d1->vm_start && ov_e >= d1->vm_end)
        {
            prev->vm_next = d1->vm_next;
            os_free(d1, sizeof(*d1));
            stats->num_vm_area--;
            d1 = prev->vm_next;
        }
        /* Overlap at beginning */
        else if (ov_s <= d1->vm_start) 
        {
            d1->vm_start = ov_e;
            prev = d1;
            d1 = d1->vm_next;
        }
        /* Overlap at end */
        else if (ov_e >= d1->vm_end) 
        {
            d1->vm_end = ov_s;
            prev = d1;
            d1 = d1->vm_next;
        }
        /* Split interior */
        else 
        {
            struct vm_area *new_vma = os_alloc(sizeof(*new_vma));
            if (!new_vma) return -ENOMEM;
            new_vma->vm_start = ov_e;
            new_vma->vm_end = d1->vm_end;
            new_vma->access_flags = d1->access_flags;
            new_vma->vm_next = d1->vm_next;
            d1->vm_end = ov_s;
            d1->vm_next = new_vma;
            stats->num_vm_area++;
            prev = new_vma;
            d1 = new_vma->vm_next;
        }
    }
    return 0;
}


long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    return -1;
}




/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */



 /**
  * cfork system call implemenations
  * The parent returns the pid of child process. The return path of
  * the child process is handled separately through the calls at the 
  * end of this function (e.g., setup_child_context etc.)
  */
 
 
long do_cfork()
{
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    /* Do not modify above lines
    * 
    * */   
    //--------------------- Your code [start]---------------/
      
 
    //--------------------- Your code [end] ----------------/
     
    /*
    * The remaining part must not be changed
    */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}
 
 
 
 /* Cow fault handling, for the entire user address space
  * For address belonging to memory segments (i.e., stack, data) 
  * it is called when there is a CoW violation in these areas. 
  *
  * For vm areas, your fault handler 'vm_area_pagefault'
  * should invoke this function
  * */
 
long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    return -1;
}
