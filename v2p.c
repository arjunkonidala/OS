#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>
#include <context.h>
#include <string.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */

/* If these aren’t in your headers already… */

#ifndef OS_PT_REG
#define OS_PT_REG 0
#endif
#ifndef USER_REG
#define USER_REG 1
#endif

/* Page size = 1 << PAGE_SHIFT */
#define PAGE_SHIFT 12   /* 4 KB pages */
#define PAGE_SIZE (1ULL << PAGE_SHIFT)

/* Helpers for multi-level indexing */
#define PGD_INDEX(x)   (((x) >> 39) & 0x1FF)
#define PUD_INDEX(x)   (((x) >> 30) & 0x1FF)
#define PMD_INDEX(x)   (((x) >> 21) & 0x1FF)
#define PTE_INDEX(x)   (((x) >> 12) & 0x1FF)

/* PTE flag bits */
#define PTE_PRESENT    (1ULL << 0)
#define PTE_RW         (1ULL << 1)
#define PTE_USER       (1ULL << 2)


// #define PAGE_SIZE    4096                  
#define PGD_SHIFT    39
#define PUD_SHIFT    30
#define PMD_SHIFT    21
#define PTE_SHIFT    12
#define PTRS_PER_PT  512ULL

/* Page‑fault error codes from assignment */
#define ERR_CODE_READ    0x4
#define ERR_CODE_WRITE   0x6
#define ERR_CODE_PROT    0x7

/* PTE flag bits (as in gemOS/page.h) */
#define PTE_P   (1ULL << 0)
#define PTE_W   (1ULL << 1)
#define PTE_U   (1ULL << 2)
#define FOUR_KB 4096
#define ADDR_SHIFT 12
#define OS_PT_REG 1
#define USER_REG 2

static inline u64 va_to_index(u64 va, int shift) 
{
    return (va >> shift) & (PTRS_PER_PT - 1);
}

/* Round up to page multiple */
static u64 align_len(u64 len) {
    return ((len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
}


static u64 align_length(u64 len) 
{
    return ((len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
}
 
static int range_overlap(u64 s1, u64 e1, u64 s2, u64 e2)
{
    return (s1 < e2 && s2 < e1);
}
 


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
            u64 hole_start = prev->vm_end < MMAP_AREA_START ? MMAP_AREA_START : prev->vm_end;
            u64 hole_end = iter->vm_start > MMAP_AREA_END ? MMAP_AREA_END : iter->vm_start;
            if (hole_end - hole_start >= length_aligned)
            {
                start = hole_start;
                do_insert = 1;
                break;
            }
        }

        if (!do_insert)                                                                // after the last VMA 
        {
            u64 hole_start = prev->vm_end < MMAP_AREA_START ? MMAP_AREA_START : prev->vm_end;
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



/** Part1 - 2nd Function --- munmap system call implementation ***********/


long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (length <= 0) return -EINVAL;
    u64 len   = align_length(length);
    u64 start = addr;
    u64 end   = addr + len;
    u64 *pgd_tbl = (u64*)osmap(current->pgd);                                       /* 0) Free any already-mapped physical pages in [start,end) */
    for (u64 va = start; va < end; va += PAGE_SIZE) 
    {
        u64 ent;                                                                     /* walk 4-level page table */
        u64 *pud_tbl, *pmd_tbl, *pte_tbl;

        ent = pgd_tbl[PGD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pud_tbl = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pud_tbl[PUD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pmd_tbl = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pmd_tbl[PMD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pte_tbl = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pte_tbl[PTE_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;

        os_pfn_free(USER_REG, (u32)(ent >> PAGE_SHIFT));                                      /* free and clear */
        pte_tbl[PTE_INDEX(va)] = 0;
    }

    
    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;                /* 1) Now do your existing VMA unmap logic exactly as before */
    while (iter)
    {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end)) 
        {
            prev = iter; iter = iter->vm_next;
            continue;
        }
        u64 ov_s = start > iter->vm_start ? start : iter->vm_start;
        u64 ov_e = end   < iter->vm_end   ? end   : iter->vm_end;

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end)             // fully covered
        {     
            prev->vm_next = iter->vm_next;
            os_free(iter, sizeof(*iter));                           /* stats-- if you still track them */
            
            iter = prev->vm_next;
        }
        else if (ov_s <= iter->vm_start)                            // trim front
        {                        
            iter->vm_start = ov_e;
            prev = iter; iter = iter->vm_next;
        }
        else if (ov_e >= iter->vm_end)                                  // trim back
        {                          
            iter->vm_end = ov_s;
            prev = iter; iter = iter->vm_next;
        }
        else                                                       // split interior
        {                                                   
            struct vm_area *new_vma = os_alloc(sizeof(*new_vma));
            if (!new_vma) return -ENOMEM;
            new_vma->vm_start = ov_e;
            new_vma->vm_end   = iter->vm_end;
            new_vma->access_flags = iter->access_flags;
            new_vma->vm_next  = iter->vm_next;
            iter->vm_end      = ov_s;
            iter->vm_next     = new_vma;                            /* stats += 1 if you track them */
            prev = new_vma; iter = new_vma->vm_next;
        }
    }
    return 0;
}



/**  Part1 - 3rd Function  mprotect System call implementation **************/

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (length <= 0) return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE)) return -EINVAL;
    u64 len   = align_length(length);
    u64 start = addr;
    u64 end   = addr + len;

    u64 *pgd_tbl = (u64*)osmap(current->pgd);                                       /* 0) Update any already-mapped pages’ PTEs to reflect new prot */
    for (u64 va = start; va < end; va += PAGE_SIZE) 
    {
        u64 ent;
        u64 *pud_tbl, *pmd_tbl, *pte_tbl;

        ent = pgd_tbl[PGD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pud_tbl = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pud_tbl[PUD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pmd_tbl = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pmd_tbl[PMD_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;
        pte_tbl = (u64*)osmap(ent >> PAGE_SHIFT);

        ent = pte_tbl[PTE_INDEX(va)];
        if (!(ent & PTE_PRESENT)) continue;

        
        u32 pfn = (u32)(ent >> PAGE_SHIFT);                                         /* rebuild leaf */
        u64 flags = PTE_PRESENT | PTE_USER | ((prot == (PROT_READ|PROT_WRITE)) ? PTE_RW : 0);
        pte_tbl[PTE_INDEX(va)] = (pfn << PAGE_SHIFT) | flags;
    }

    struct vm_area *dummy = current->vm_area, *prev = dummy, *iter = dummy->vm_next;                        /* 1) Now do your existing VMA mprotect logic exactly as before */
    while (iter)
    {
        if (!range_overlap(start, end, iter->vm_start, iter->vm_end))
        {
            prev = iter; iter = iter->vm_next;
            continue;
        }
        u64 ov_s = start > iter->vm_start ? start : iter->vm_start;
        u64 ov_e = end   < iter->vm_end   ? end   : iter->vm_end;

        if (ov_s <= iter->vm_start && ov_e >= iter->vm_end)                          // fully covered
        {
            iter->access_flags = prot;
            prev = iter; iter = iter->vm_next;
        }
        else if (ov_s <= iter->vm_start)                                            // split front 
        {
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            post->vm_start = ov_e;
            post->vm_end   = iter->vm_end;
            post->access_flags = iter->access_flags;
            post->vm_next  = iter->vm_next;
            iter->vm_end   = ov_e;
            iter->access_flags = prot;
            iter->vm_next  = post;                                                   /* stats++ if tracked */
            prev = post; iter = post->vm_next;
        }
        else if (ov_e >= iter->vm_end)                                               // split back
        {   
            struct vm_area *pre = os_alloc(sizeof(*pre));
            if (!pre) return -ENOMEM;
            pre->vm_start = iter->vm_start;
            pre->vm_end   = ov_s;
            pre->access_flags = iter->access_flags;
            pre->vm_next  = iter->vm_next;
            iter->vm_start = ov_s;
            iter->access_flags = prot;
            iter->vm_next  = pre;                                                                   /* stats++ if tracked */
            prev = pre; iter = pre->vm_next;
        }
        else                                                         // interior split
        {                                               
            struct vm_area *post = os_alloc(sizeof(*post));
            if (!post) return -ENOMEM;
            post->vm_start = ov_e;
            post->vm_end   = iter->vm_end;
            post->access_flags = iter->access_flags;
            post->vm_next  = iter->vm_next;

            struct vm_area *mid = os_alloc(sizeof(*mid));
            if (!mid) return -ENOMEM;
            mid->vm_start  = ov_s;
            mid->vm_end    = ov_e;
            mid->access_flags = prot;
            mid->vm_next   = post;

            iter->vm_end   = ov_s;
            iter->vm_next  = mid;                           /* stats += 2 if tracked */
            prev = post; iter = post->vm_next;
        }
    }
    return 0;
}












/**************************************** PART2 ********************************************/

/******** Part 2 – 1st Page-fault handler for lazy allocation ************/

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    struct vm_area *vma;

    for (vma = current->vm_area->vm_next; vma; vma = vma->vm_next)                      /* 1) Find the VMA covering this address */
    {
        if (addr >= vma->vm_start && addr < vma->vm_end) break;
    }
    if (!vma) return -1;                                                                /* no VMA ⇒ invalid access */
    
    int not_present   = !(error_code & 0x1);                                            /* 2) Decode the fault bits (x86 P=bit0, W=bit1, U=bit2) */ /* P=0 ⇒ page not present */
    int write_fault   =  (error_code & 0x2);                                            /* W=1 ⇒ write access */
    int present_fault =  (error_code & 0x1);                                            /* P=1 ⇒ protection/COW fault */

    if (present_fault && write_fault)                                                   /* 3) Write to a present page = COW break? */
    {
        if (!(vma->access_flags & PROT_WRITE)) return -1;                               /* truly read-only ⇒ segfault */
        return handle_cow_fault(current, addr, vma->access_flags);
    }
    
    if (not_present)                                                                    /* 4) Lazy-allocate on a not-present fault */
    {   
        if (write_fault && !(vma->access_flags & PROT_WRITE)) return -1;                /* write to R-only VMA ⇒ invalid */
        u32 new_pfn = os_pfn_alloc(USER_REG);                                           /* allocate a fresh user-frame */
        
        if (!new_pfn) return -1;
        void *page = osmap(new_pfn);
        memset(page, 0, PAGE_SIZE);

        u64 *pgd = (u64 *)osmap(current->pgd);                                          /* now walk/create the 4-level page table and install the PTE */
        u64 *pud, *pmd, *pte;
        u64 entry;

        if (!(pgd[PGD_INDEX(addr)] & PTE_PRESENT))                                      /* PGD */
        {
            u32 pfn = os_pfn_alloc(OS_PT_REG);
            pgd[PGD_INDEX(addr)] = (pfn << PAGE_SHIFT) | PTE_PRESENT | PTE_RW | PTE_USER;
        }
        pud = (u64 *)osmap(pgd[PGD_INDEX(addr)] >> PAGE_SHIFT);

        if (!(pud[PUD_INDEX(addr)] & PTE_PRESENT))                                      /* PUD */
        {
            u32 pfn = os_pfn_alloc(OS_PT_REG);
            pud[PUD_INDEX(addr)] = (pfn << PAGE_SHIFT) | PTE_PRESENT | PTE_RW | PTE_USER;
        }
        pmd = (u64 *)osmap(pud[PUD_INDEX(addr)] >> PAGE_SHIFT);

        
        if (!(pmd[PMD_INDEX(addr)] & PTE_PRESENT))                                      /* PMD */
        {
            u32 pfn = os_pfn_alloc(OS_PT_REG);
            pmd[PMD_INDEX(addr)] = (pfn << PAGE_SHIFT) | PTE_PRESENT | PTE_RW | PTE_USER;
        }
        pte = (u64 *)osmap(pmd[PMD_INDEX(addr)] >> PAGE_SHIFT);

        
        entry = (new_pfn << PAGE_SHIFT) | PTE_PRESENT | PTE_USER;                       /* PTE */
        if (vma->access_flags & PROT_WRITE) entry |= PTE_RW;
        pte[PTE_INDEX(addr)] = entry;

        return 1;                                                                       /* success */
    }
    return -1;                                                                          /* any other case is invalid */
}

/******** Part 2 – 2nd Modifications for munmap function are done in the vm_area_unmap above     ************/

/******** Part 2 – 3rd Modifications for mprotect function are done in the vm_area_mprotect above ************/













/**************************************** PART3 ********************************************/


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
       
    //copy the address space
    new_ctx->ppid=ctx->pid; //ppid done
    struct vm_area* x=ctx->vm_area;
    struct vm_area* y=new_ctx->vm_area;
    y=os_alloc(sizeof(struct vm_area));  //assume link not empty
    while(1){
    y->vm_start=x->vm_start;
    y->vm_end=x->vm_end;
    y->access_flags=x->access_flags;
    if(x->vm_next==0){
        y->vm_next=0;
        break;
    }
     struct vm_area* z=os_alloc(sizeof(struct vm_area));
     y->vm_next=z;
     y=z;
     }
     // page table entries
     new_ctx->pgd=os_pfn_alloc(OS_PT_REG);
     u32 child_pgd = os_pfn_alloc(OS_PT_REG);
     new_ctx->pgd = child_pgd;
 
     for (int i = 0; i < 4; i++) {
        
         for (u64 addr = ctx->mms[i].start; addr < ctx->mms[i].next_free; addr += 4096) {
             u64 *p_e = get_user_pte(ctx, addr, 0);
             if (!(!p_e || !(*p_e & PTE_P)) ){ //if valid creates entries
             u64 pf = *p_e >> 12;
             get_pfn(pf);  // increase refcount
             *p_e &= ~PTE_W;  //  remove write access
             u64 *child_pte = get_user_pte(new_ctx, addr, 1);   //page is used then we create page entry in new_ctx
             *child_pte = (*p_e);
         }
         }
     }
     struct vm_area *v = ctx->vm_area;
     while (1) {
         for (u64 addr = v->vm_start; addr < v->vm_end; addr += FOUR_KB) {
             u64 *parent_pte = get_user_pte(ctx, addr, 0);
             if (!(!parent_pte || !(*parent_pte & PTE_P))) {
 
             u64 pf = *parent_pte >> 12;
             get_pfn(pf);        // increase refcount
             *parent_pte &= ~PTE_W;  //  remove write access
 
             u64 *child_pte = get_user_pte(new_ctx, addr, 1);    //page is used then we create page entry in new_ctx
             *child_pte = (*parent_pte);
         }}
         v = v->vm_next;
         if(!v)break;
     }
 
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