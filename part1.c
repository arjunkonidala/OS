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

#define FOUR_KB 0x1000

#define PGD_MASK 0xFF8000000000
#define PUD_MASK 0x7FC0000000
#define PMD_MASK 0x3FE00000
#define PTE_MASK 0x1FF000

/* Page‑fault error codes from assignment */
#define ERR_CODE_READ    0x4
#define ERR_CODE_WRITE   0x6
#define ERR_CODE_PROT    0x7

/* PTE flag bits (as in gemOS/page.h) */
#define PTE_P   (1ULL << 0)
#define PTE_W   (1ULL << 1)
#define PTE_U   (1ULL << 2)

#define PTE_SIZE 0x8
#define PT_SIZE 0x200
#define ADDR_SHIFT 0xC

static u64 pgsizecalc(u64 len) 
{
    return ((len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
}
 

static int range_overlap(u64 s1, u64 e1, u64 s2, u64 e2)
{
    return (s1 < e2 && s2 < e1);
}
void freePFN(long addr) {

    struct exec_context *current = get_current_ctx();

    // first we update the page table entry

    // Compute offsets required in each level of the page table
    u64 pgdIdx = (addr & PGD_MASK) >> PGD_SHIFT;
    u64 pudIdx = (addr & PUD_MASK) >> PUD_SHIFT;
    u64 pmdIdx = (addr & PMD_MASK) >> PMD_SHIFT;
    u64 pteIdx = (addr & PTE_MASK) >> PTE_SHIFT;

    // calculate the entry of in the first level of the page table
    u64 pgd_entry_VA = ((u64)osmap(current->pgd)) + (pgdIdx)*(PTE_SIZE);

    if( ( *((u64*)pgd_entry_VA) & 1 ) == 0) {
        return;
    }

    // calculate the entry of in the second level of the page table
    u64 pud_entry_VA = ((u64)osmap( ( ( *((u64*)pgd_entry_VA)  ) >> ADDR_SHIFT) ) ) + (pudIdx)*(PTE_SIZE);

    if( ( *((u64*)pud_entry_VA) & 1 ) == 0) {
        return;
    }

    // calculate the entry of in the third level of the page table
    u64 pmd_entry_VA = ((u64)osmap( ( ( *((u64*)pud_entry_VA)  ) >> ADDR_SHIFT) ) ) + (pmdIdx)*(PTE_SIZE);

    if( ( *((u64*)pmd_entry_VA) & 1 ) == 0) {
        return;
    }

    // calculate the entry of in the final level of the page table
    u64 pte_entry_VA = ((u64)osmap( ( ( *((u64*)pmd_entry_VA)  ) >> ADDR_SHIFT) ) ) + (pteIdx)*(PTE_SIZE);

    if( ( *((u64*)pte_entry_VA) & 1 ) == 0) {
        return;
    }

    // extract the pfn number from the entry
    u64 pfn = ( *((u64*)pte_entry_VA) >> ADDR_SHIFT );

    // set the entry to zero
    *((u64*)pte_entry_VA) = 0x0;

    // decrement the reference count of the pfn
    if(get_pfn_refcount(pfn) == 0) return;
    put_pfn(pfn);
    
    // check the ref_count of the pfn before unmapping
    if(get_pfn_refcount(pfn) == 0) {
        // now we actually deallocate the pfn
        os_pfn_free(USER_REG,pfn);
    }
   
}

// helper function which deallocates all pfns from vma to be unmapped
void freeAllPFNs(long addr_start, long addr_end) {

    // find the number of pages to be deallocated
    int numPages = (addr_end - addr_start) / (FOUR_KB);

    // iterate through each page and deallocate it
    for(int i = 0; i < numPages; i++) {
        freePFN(addr_start + i*(FOUR_KB));
    }
}
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot) 
{
    if (length <= 0) return -EINVAL;

    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE)) return -EINVAL;

    u64 len = pgsizecalc(length);
    u64 start = addr;
    u64 end = addr + len;
    
    struct vm_area *head = current->vm_area, *d = head, *d1 = head->vm_next;

    while (d1)
    {
        //if addr,addr+len lies completely
        if((d1->vm_start>=addr)&&(d1->vm_end<=addr+len&&(d1->access_flags!=prot))){
            
            if(d1->vm_start>addr&&d1->vm_end<addr)
            {
                struct vm_area* x=os_alloc(sizeof(struct vm_area));
                x->vm_start=d1->vm_start;
                x->vm_end=addr;
                x->access_flags=d1->access_flags;
                d->vm_next=x;
                struct vm_area* x1=os_alloc(sizeof(struct vm_area));
                x->vm_next=x1;
                x1->vm_start=addr;
                x1->vm_end=addr+len;
                x1->access_flags=prot;
                struct vm_area* x2=os_alloc(sizeof(struct vm_area));
                x1->vm_next=x2;
                x2->vm_start=addr+len;
                x2->vm_end=d1->vm_end;
                x2->access_flags=d1->access_flags;
                x2->vm_next=d1->vm_next;
                os_free(d1, sizeof(d1));
                

                
                stats->num_vm_area+=2;
                return 0;
            }
            if((d1->vm_start==addr)&&(d1->vm_end<addr+len)){
                struct vm_area* x1=os_alloc(sizeof(struct vm_area));
                
                x1->vm_start=addr+len;
                x1->vm_end=d1->vm_end;
                x1->access_flags=d1->access_flags;
                x1->vm_next=d1->vm_next;
                d->vm_next=x1;
                struct vm_area *x2=os_alloc(sizeof(struct vm_area));

                os_free(d1, sizeof(d1));
                return 0;
            }
            if(d1->vm_start<addr&&d1->vm_end==addr+len){
                struct vm_area* x=os_alloc(sizeof(struct vm_area));
                x->vm_start=d1->vm_start;
                x->vm_end=addr;
                x->access_flags=d1->access_flags;
                x->vm_next=d1->vm_next;
                d->vm_next=x;
                os_free(d1, sizeof(d1));
                
                return 0;
            }
            if(d1->vm_start==addr&&d1->vm_end==addr+len){
                d->vm_next=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area--;
                return 0;
            }


        }
        //if d1 partially overlap from back
        else if(d1->vm_start<=addr&&d1->vm_end<addr+len){
            if(d1->vm_start<addr){
            struct vm_area* x=os_alloc(sizeof(struct vm_area));
            x->vm_start=d1->vm_start;
            x->vm_end=addr;
            x->access_flags=d1->access_flags;
            x->vm_next=d1->vm_next;
            d->vm_next=x;
            struct vm_area* t=d1->vm_next;
            os_free(d1, sizeof(d1));
            d1=t;
            }
            else{
                d->vm_next=d1->vm_next;
                struct vm_area* t=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area--;
                d1=t;
            }
            if(d1==0)return 0;
        }//from front
        else if(d1->vm_start>addr&&d1->vm_end<=addr+len){
            if(d1->vm_end<addr+len){
            struct vm_area* x=os_alloc(sizeof(struct vm_area));
            x->vm_start=addr+len;
            x->vm_end=d1->vm_end;
            x->access_flags=d1->access_flags;
            x->vm_next=d1->vm_next;
            d->vm_next=x;
            struct vm_area* t=d1->vm_next;
            os_free(d1, sizeof(d1));
            d1=t;
            }
            else{
                d->vm_next=d1->vm_next;
                struct vm_area* t=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area--;
                d1=t;
            }
            return 0;
        }
        else if((d1->vm_start>addr && d1->vm_end<addr+len)){
            d->vm_next=d1->vm_next;
                struct vm_area* t=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area--;
                d1=t;
                if(d1==0)return 0;
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

    struct vm_area *d, *d1;
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
    d = head;
    for (d1 = head->vm_next; d1; d = d1, d1 = d1->vm_next) 
    {
        u64 hole_start;
        if (d->vm_end < MMAP_AREA_START )
        {
            hole_start = MMAP_AREA_START;
        }
        else hole_start = d->vm_end;


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
        if (d->vm_end < MMAP_AREA_START)
        {
            hole_start = MMAP_AREA_START;
        }
        else hole_start = d->vm_end;

        // u64 hole_start = d->vm_end < MMAP_AREA_START ? MMAP_AREA_START : d->vm_end;

        if (MMAP_AREA_END - hole_start >= length_aligned) { start = hole_start; goto create; }
    }
    return -ENOMEM;

create:
    /* Insert new VMA */
    d = head;
    while (d->vm_next && d->vm_next->vm_start < start) d = d->vm_next;
    struct vm_area *vm = os_alloc(sizeof(*vm));
    if (!vm) return -ENOMEM;
    vm->vm_start = start;
    vm->vm_end = start + length_aligned;
    vm->access_flags = prot;
    vm->vm_next = d->vm_next;
    d->vm_next = vm;
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
    /* Merge with d */
    if (d != head && d->vm_end == vm->vm_start && d->access_flags == vm->access_flags) 
    {
        d->vm_end = vm->vm_end;
        d->vm_next = vm->vm_next;
        os_free(vm, sizeof(*vm));
        stats->num_vm_area--;
        start = d->vm_start;
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
    struct vm_area *head = current->vm_area, *d = head, *d1 = head->vm_next;
    freeAllPFNs(addr,addr+len);
    while (d1) 
    {
        //if d1 lies completely
        if((d1->vm_start>=addr)&&(d1->vm_end<=addr+len)){
            
            if(d1->vm_start>addr&&d1->vm_end<addr){
                struct vm_area* x=os_alloc(sizeof(struct vm_area));
                x->vm_start=d1->vm_start;
                x->vm_end=addr;
                x->access_flags=d1->access_flags;
                d->vm_next=x;
           
                struct vm_area* x1=os_alloc(sizeof(struct vm_area));
                x->vm_next=x1;
                x1->vm_start=addr+len;
                x1->vm_end=d1->vm_end;
                x1->access_flags=d1->access_flags;
                x1->vm_next=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area++;
                return 0;
            }
            if((d1->vm_start==addr)&&(d1->vm_end<addr+len)){
                struct vm_area* x1=os_alloc(sizeof(struct vm_area));
                
                x1->vm_start=addr+len;
                x1->vm_end=d1->vm_end;
                x1->access_flags=d1->access_flags;
                x1->vm_next=d1->vm_next;
                d->vm_next=x1;
                os_free(d1, sizeof(d1));
                return 0;
            }
            if(d1->vm_start<addr&&d1->vm_end==addr+len){
                struct vm_area* x=os_alloc(sizeof(struct vm_area));
                x->vm_start=d1->vm_start;
                x->vm_end=addr;
                x->access_flags=d1->access_flags;
                x->vm_next=d1->vm_next;
                d->vm_next=x;
                os_free(d1, sizeof(d1));
                
                return 0;
            }
            if(d1->vm_start==addr&&d1->vm_end==addr+len){
                d->vm_next=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area--;
                return 0;
            }


        }
        //if d1 partially overlap from back
        else if(d1->vm_start<=addr&&d1->vm_end<addr+len){
            if(d1->vm_start<addr){
            struct vm_area* x=os_alloc(sizeof(struct vm_area));
            x->vm_start=d1->vm_start;
            x->vm_end=addr;
            x->access_flags=d1->access_flags;
            x->vm_next=d1->vm_next;
            d->vm_next=x;
            struct vm_area* t=d1->vm_next;
            os_free(d1, sizeof(d1));
            d1=t;
            }
            else{
                d->vm_next=d1->vm_next;
                struct vm_area* t=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area--;
                d1=t;
            }
            if(d1==0)return 0;
        }//from front
        else if(d1->vm_start>addr&&d1->vm_end<=addr+len){
            if(d1->vm_end<addr+len){
            struct vm_area* x=os_alloc(sizeof(struct vm_area));
            x->vm_start=addr+len;
            x->vm_end=d1->vm_end;
            x->access_flags=d1->access_flags;
            x->vm_next=d1->vm_next;
            d->vm_next=x;
            struct vm_area* t=d1->vm_next;
            os_free(d1, sizeof(d1));
            d1=t;
            }
            else{
                d->vm_next=d1->vm_next;
                struct vm_area* t=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area--;
                d1=t;
            }
            return 0;
        }
        else if((d1->vm_start>addr && d1->vm_end<addr+len)){
            d->vm_next=d1->vm_next;
                struct vm_area* t=d1->vm_next;
                os_free(d1, sizeof(d1));
                stats->num_vm_area--;
                d1=t;
                if(d1==0)return 0;
        }

        

    }
    return -EINVAL;
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
