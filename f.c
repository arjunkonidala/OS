#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */

                
#define PGD_SHIFT    39
#define PUD_SHIFT    30
#define PMD_SHIFT    21
#define PTE_SHIFT    12
#define PTRS_PER_PT  512ULL





#define PGD_MASK 0xFF8000000000
#define PUD_MASK 0x7FC0000000
#define PMD_MASK 0x3FE00000
#define PTE_MASK 0x1FF000

#define ERR_CODE_READ    0x4
#define ERR_CODE_WRITE   0x6
#define ERR_CODE_PROT    0x7
#define PTE_P   (1ULL << 0)
#define PTE_W   (1ULL << 1)
#define PTE_U   (1ULL << 2)

#define PTE_SIZE 0x8
#define PT_SIZE 0x200
#define ADDR_SHIFT 0xC
static int range_overlap(u64 s1, u64 e1, u64 s2, u64 e2)
{
    return (s1 < e2 && s2 < e1);
}
static u64 pgsizecalc(u64 len) 
{
    return ((len + 0x1000 - 1) / 0x1000) * 0x1000;
}
 

void uPTPp(u64 pfn, u64 pgd_e, u64 pud_e, u64 pmd_e) {
    u64 a_ptr = (u64)osmap( ( *((u64*)pmd_e) ) >> 12) ;
    while(a_ptr < (u64)osmap( ( *((u64*)pmd_e) ) >> 12) + PT_SIZE) {
       
        if( ( ( ( *((u64*)a_ptr) ) >> 0x3) & 0x1 ) ==  0x1 ) return;
        a_ptr += PTE_SIZE;
    }
    *((u64*)pmd_e) &= ~(0x3);
    a_ptr = (u64)osmap( ( *((u64*)pud_e) ) >> 12) ;
    while(a_ptr < (u64)osmap( ( *((u64*)pud_e) ) >> 12) + PT_SIZE) {
        
        if( ( ( ( *((u64*)a_ptr) ) >> 0x3) & 0x1 ) ==  0x1 ) return;
        a_ptr += PTE_SIZE;
    }
    *((u64*)pud_e) &= ~(0x3);
    a_ptr = (u64)osmap( ( *((u64*)pgd_e) ) >> 12) ;
    while(a_ptr < (u64)osmap( ( *((u64*)pgd_e) ) >> 12) + PT_SIZE) {
        if( ( ( ( *((u64*)a_ptr) ) >> 0x3) & 0x1 ) ==  0x1 ) return;
        a_ptr += PTE_SIZE;
        asm volatile("invlpg (%0);" ::"r"(a_ptr) : "memory");
    }
    *((u64*)pgd_e) &= ~(0x3);
    return;
}

void f_pfn(long addr) {
    struct exec_context *current = get_current_ctx();
    u64 pgdIdx = (addr & PGD_MASK) >> PGD_SHIFT;
    u64 pudIdx = (addr & PUD_MASK) >> PUD_SHIFT;
    u64 pmdIdx = (addr & PMD_MASK) >> PMD_SHIFT;
    u64 pteIdx = (addr & PTE_MASK) >> PTE_SHIFT;

    u64 pgd_e = ((u64)osmap(current->pgd)) + (pgdIdx)*(PTE_SIZE);

    if( ( *((u64*)pgd_e) & 1 ) == 0) {
        return;
    }

    u64 pud_e = ((u64)osmap( ( ( *((u64*)pgd_e)  ) >> ADDR_SHIFT) ) ) + (pudIdx)*(PTE_SIZE);

    if( ( *((u64*)pud_e) & 1 ) == 0) {
        return;
    }

    u64 pmd_e = ((u64)osmap( ( ( *((u64*)pud_e)  ) >> ADDR_SHIFT) ) ) + (pmdIdx)*(PTE_SIZE);

    if( ( *((u64*)pmd_e) & 1 ) == 0) {
        return;
    }

    u64 pte_entry_VA = ((u64)osmap( ( ( *((u64*)pmd_e)  ) >> ADDR_SHIFT) ) ) + (pteIdx)*(PTE_SIZE);

    if( ( *((u64*)pte_entry_VA) & 1 ) == 0) {
        return;
    }

    u64 pfn = ( *((u64*)pte_entry_VA) >> ADDR_SHIFT );

    *((u64*)pte_entry_VA) = 0x0;

    if(get_pfn_refcount(pfn) == 0) return;
    put_pfn(pfn);
    
    if(get_pfn_refcount(pfn) == 0) {
        os_pfn_free(USER_REG,pfn);
    }
   
    asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
}

void freeAllPFNs(long addr_start, long addr_end) {

    int numPages = (addr_end - addr_start) / (0x1000);

    for(int i = 0; i < numPages; i++) {
     f_pfn(addr_start + i*(0x1000));
    }
}
void updatePFN(long addr, int prot) {

    struct exec_context *current = get_current_ctx();

    u64 pgdIdx = (addr & PGD_MASK) >> PGD_SHIFT;
    u64 pudIdx = (addr & PUD_MASK) >> PUD_SHIFT;
    u64 pmdIdx = (addr & PMD_MASK) >> PMD_SHIFT;
    u64 pteIdx = (addr & PTE_MASK) >> PTE_SHIFT;

    u64 pgd_e = ((u64)osmap(current->pgd)) + (pgdIdx)*(PTE_SIZE);

    if( ( *((u64*)pgd_e) & 1 ) == 0) {
        return;
    }

    u64 pud_e = ((u64)osmap( ( ( *((u64*)pgd_e)  ) >> ADDR_SHIFT) ) ) + (pudIdx)*(PTE_SIZE);

    if( ( *((u64*)pud_e) & 1 ) == 0) {
        return;
    }

    u64 pmd_e = ((u64)osmap( ( ( *((u64*)pud_e)  ) >> ADDR_SHIFT) ) ) + (pmdIdx)*(PTE_SIZE);

    if( ( *((u64*)pmd_e) & 1 ) == 0) {
        return;
    }

    u64 pte_entry_VA = ((u64)osmap( ( ( *((u64*)pmd_e)  ) >> ADDR_SHIFT) ) ) + (pteIdx)*(PTE_SIZE);

    if( ( *((u64*)pte_entry_VA) & 1 ) == 0) {
        return;
    }

    if(prot == 1) {
        *((u64*)pte_entry_VA) &= ~(0x8);

        u64 pfn = ( ( *((u64*)pte_entry_VA)  ) >> ADDR_SHIFT );
        uPTPp(pfn,pgd_e,pud_e,pmd_e);
    }
    else {

        u64 pfn = ( ( *((u64*)pte_entry_VA)  ) >> ADDR_SHIFT );
        if(get_pfn_refcount(pfn) > 1) {
            u64 new_pfn = os_pfn_alloc(USER_REG);
            *((u64*)pte_entry_VA) = (new_pfn << ADDR_SHIFT) | 0x11;
            *((u64*)pte_entry_VA) |= 0x8;
            
            put_pfn(pfn);
            if(get_pfn_refcount(pfn) == 0) {
                os_pfn_free(USER_REG,pfn);
            }
        }

        *((u64*)pte_entry_VA) |= 0x8;
        *((u64*)pmd_e) |= 0x8;
        *((u64*)pud_e) |= 0x8;
        *((u64*)pgd_e) |= 0x8;

    }
    
    asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
}
void updateAllPFNs(long addr_start, long addr_end, int prot) {

    int numPages = (addr_end - addr_start) / (0x1000);

    for(int i = 0; i < numPages; i++) {
        updatePFN(addr_start + i*(0x1000), prot);
    }
}
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot) 
{
    if (length <= 0) return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE)) return -EINVAL ;

    u64 len = pgsizecalc(length);
    u64 start = addr;
    u64 end = addr + len;
    updateAllPFNs(addr,addr+len,prot);
    struct vm_area *head = current->vm_area, *d = head, *d1 = head->vm_next;

    while (d1&&d1->vm_start<=addr)
    {
        //if addr,addr+len lies completely
        if((d1->vm_start<=addr)&&(d1->vm_end>=addr+len)&&(d1->access_flags!=prot)){
            
            if(d1->vm_start<addr&&d1->vm_end>addr+len)
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
                stats->num_vm_area+=2;  //imp
                return 0;
            }
            if((d1->vm_start==addr)&&(d1->vm_end>addr+len)){
                struct vm_area* x1=os_alloc(sizeof(struct vm_area));
                
                x1->vm_start=addr;
                x1->vm_end=addr+len;
                x1->access_flags=prot;
                x1->vm_next=d1;
                d->vm_next=x1;
                d1->vm_start=addr+len;
                stats->num_vm_area+=1;
                //join 
                goto exit;
            }
            if(d1->vm_start<addr&&d1->vm_end==addr+len){
                struct vm_area* x=os_alloc(sizeof(struct vm_area));
                x->vm_start=addr;
                x->vm_end=d1->vm_end;
                x->access_flags=prot;
                x->vm_next=d1->vm_next;
                d1->vm_next=x;
                d1->vm_end=addr;
                stats->num_vm_area+=1;
                //join
                goto exit;
            }
            if(d1->vm_start==addr&&d1->vm_end==addr+len){
                d1->access_flags=prot;
                goto exit;
                
            }


        }
        
        //if d1 partially overlap from back
        else if(d1->vm_start<=addr&&d1->vm_end<addr+len&&d1->access_flags!=prot){
            if(d1->vm_start<addr){
            struct vm_area* x=os_alloc(sizeof(struct vm_area));
            x->vm_start=addr;
            x->vm_end=d1->vm_end;
            x->access_flags=prot;
            x->vm_next=d1->vm_next;
            d1->vm_end=addr;
            d1->vm_next=x;
            d=d->vm_next;
            d1=d1->vm_next;
            stats->num_vm_area+=1;
            }
            else{
                d1->access_flags=prot;
            }
            
        }//from front

        else if(d1->vm_start>addr&&d1->vm_end<=addr+len&&d1->access_flags!=prot){
            if(d1->vm_end<addr+len){
            struct vm_area* x=os_alloc(sizeof(struct vm_area));
            x->vm_start=addr+len;
            x->vm_end=d1->vm_end;
            d1->vm_end=addr+len;
            x->access_flags=d1->access_flags;
            d1->access_flags=prot;
            x->vm_next=d1->vm_next;
            d1->vm_next=x;
            d=d->vm_next;
            d1=d1->vm_next;
            stats->num_vm_area+=1;
            }
            else{
                d1->access_flags=prot;
            }
            return 0;
        }
        else if((d1->vm_start>addr && d1->vm_end<addr+len)){
            d1->access_flags=prot;
        }

        d=d1;
        d1=d1->vm_next;
    }
    exit:
    //merge
    struct vm_area* i1,*i2;
    i1=current->vm_area;
    i2=i1->vm_next;
    while(i2){
        if(i1->vm_end==i2->vm_start&&i1->access_flags==i2->access_flags){
            //merge
            i1->vm_end=i2->vm_end;
            i1->vm_next=i2->vm_next;
            i2=i2->vm_next;
            os_free(i2,sizeof(i2));
        }
        else{
        i1=i1->vm_next;
        i2=i2->vm_next;
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
    /* ——— initialize the dummy head if this is the first mmap ——— */
    if (!head) {
        struct vm_area *x = os_alloc(sizeof(*x));
        if (!x) return -ENOMEM;
        x->vm_start     = MMAP_AREA_START;
        x->vm_end       = MMAP_AREA_START + 0x1000;
        x->access_flags = 0;
        x->vm_next      = NULL;
        current->vm_area = x;
        stats->num_vm_area = 1;
        head = x;
    }

    /* ——— validate arguments ——— */
    if (length <= 0 || length > (2 << 20))
        return -EINVAL;
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE))
        return -EINVAL;
    if ((flags & MAP_FIXED) && addr == 0)
        return -EINVAL;

    u64 length_aligned = pgsizecalc(length);
    int use_fixed      = (flags & MAP_FIXED) != 0;
    u64 start          = 0;
    int found          = 0;

    /* ——— MAP_FIXED: must fit exactly and not overlap ——— */
    if (use_fixed) {
        u64 end = addr + length_aligned;
        if (addr < MMAP_AREA_START || end > MMAP_AREA_END)
            return -EINVAL;
        for (struct vm_area *q = head->vm_next; q; q = q->vm_next) {
            if (range_overlap(addr, end, q->vm_start, q->vm_end))
                return -EINVAL;
        }
        start = addr;
        found = 1;
    }

    /* ——— non‐fixed hint: try the user’s hint if it fits ——— */
    if (!found && addr) {
        u64 hint_start = addr;
        u64 hint_end   = addr + length_aligned;
        if (hint_start >= MMAP_AREA_START && hint_end <= MMAP_AREA_END) {
            int ok = 1;
            for (struct vm_area *q = head->vm_next; q; q = q->vm_next) {
                if (range_overlap(hint_start, hint_end, q->vm_start, q->vm_end)) {
                    ok = 0;
                    break;
                }
            }
            if (ok) {
                start = hint_start;
                found = 1;
            }
        }
    }

    /* ——— find the first hole big enough in between existing VMAs ——— */
    if (!found) {
        struct vm_area *prev = head;
        for (struct vm_area *q = head->vm_next; q; prev = q, q = q->vm_next) {
            u64 hole_start = (prev->vm_end < MMAP_AREA_START
                              ? MMAP_AREA_START
                              : prev->vm_end);
            u64 hole_end   = (q->vm_start > MMAP_AREA_END
                              ? MMAP_AREA_END
                              : q->vm_start);
            if (hole_end - hole_start >= length_aligned) {
                start = hole_start;
                found = 1;
                break;
            }
        }
        /* ——— after the last VMA ——— */
        if (!found) {
            struct vm_area *last = head;
            while (last->vm_next) last = last->vm_next;
            u64 hole_start = (last->vm_end < MMAP_AREA_START
                              ? MMAP_AREA_START
                              : last->vm_end);
            if (MMAP_AREA_END - hole_start >= length_aligned) {
                start = hole_start;
                found = 1;
            }
        }
    }

    if (!found)
        return -ENOMEM;

    /* ——— now do the one‐off “create new VMA and merge” step ——— */
    struct vm_area *d = head;
    while (d->vm_next && d->vm_next->vm_start < start)
        d = d->vm_next;

    struct vm_area *vm = os_alloc(sizeof(*vm));
    if (!vm)
        return -ENOMEM;

    vm->vm_start     = start;
    vm->vm_end       = start + length_aligned;
    vm->access_flags = prot;
    vm->vm_next      = d->vm_next;
    d->vm_next       = vm;
    stats->num_vm_area++;

    /* merge with next */
    if (vm->vm_next &&
        vm->vm_end == vm->vm_next->vm_start &&
        vm->access_flags == vm->vm_next->access_flags) {
        struct vm_area *n = vm->vm_next;
        vm->vm_end   = n->vm_end;
        vm->vm_next  = n->vm_next;
        os_free(n, sizeof(*n));
        stats->num_vm_area--;
    }
    /* merge with previous */
    if (d != head &&
        d->vm_end == vm->vm_start &&
        d->access_flags == vm->access_flags) {
        d->vm_end   = vm->vm_end;
        d->vm_next  = vm->vm_next;
        os_free(vm, sizeof(*vm));
        stats->num_vm_area--;
        start = d->vm_start;
    }

    return (long) start;
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
        //if (addr,addr+len) lies completely

        if((d1->vm_start<=addr)&&(d1->vm_end>=addr+len)){
            
            if(d1->vm_start<addr&&d1->vm_end>addr+len){
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
            if((d1->vm_start==addr)&&(d1->vm_end>addr+len)){
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
            d=d->vm_next;
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
            d=d->vm_next;
            struct vm_area* t=d1->vm_next;
            os_free(d1, sizeof(d1));
            d=d->vm_next;
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
    return 0;;
}


// long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
// {
//     return -1;
//}

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{   //printk("%d",error_code);
    if (addr < 0)
    {
        return -EINVAL;
    }
    
    // find the vm_area corresponding to the faulting address
    struct vm_area *vma = current->vm_area;
    int flag = 0;
    while (vma != NULL)
    {
        if (vma->vm_start <= addr && vma->vm_end > addr)
        {
            flag = 1;
            break;
        }
        else if (addr < vma->vm_start)
            break;
        vma = vma->vm_next;
    }

    if (flag == 0)
    {
        return -EINVAL;
    }
    
    if (error_code == 0x6 && vma->access_flags == PROT_READ) {
       
        return -EINVAL;
        
    }

    // Another invalid fault can occur if there is a write access to a page with read only permission
    if (error_code == 0x7)
    {
        return -1;
    }

    // Manipulate Page Table

    // Compute offsets required in each level of the page table
    u64 pgdIdx = (addr & PGD_MASK) >> PGD_SHIFT;
    u64 pudIdx = (addr & PUD_MASK) >> PUD_SHIFT;
    u64 pmdIdx = (addr & PMD_MASK) >> PMD_SHIFT;
    u64 pteIdx = (addr & PTE_MASK) >> PTE_SHIFT;

    // calculate the entry of in the first level of the page table
    u64 pgd_e = ((u64)osmap(current->pgd)) + (pgdIdx)*(PTE_SIZE);

    // check if page frame has been allocated for the next level of the page table
    if( ( *((u64*)pgd_e) & 1 ) == 0) {
        // allocate pfn for pud_t
        u64 pud_pfn = os_pfn_alloc(OS_PT_REG);
        if(pud_pfn == 0) {
            return -EINVAL;
        }

        // update the pgd_entry
        *((u64*)pgd_e) = (pud_pfn << ADDR_SHIFT) | 0x1;  // set the present bit along with the pfn value
        *((u64*)pgd_e) |= 0x10;                          // set the user bit

        if(vma->access_flags == 0x3) {
            *((u64*)pgd_e) |= 0x8;                       // set the read/write bit
        }
    }

    // calculate the entry of in the second level of the page table
    u64 pud_e = ((u64)osmap( ( ( *((u64*)pgd_e)  ) >> ADDR_SHIFT) ) ) + (pudIdx)*(PTE_SIZE);

    // check if page frame has been allocated for the next level of the page table
    if( ( *((u64*)pud_e) & 1 ) == 0) {
        // allocate pfn for pmd_t
        u64 pmd_pfn = os_pfn_alloc(OS_PT_REG);
        if(pmd_pfn == 0) {
            return -EINVAL;
        }

        // update the pud_entry
        *((u64*)pud_e) = (pmd_pfn << ADDR_SHIFT) | 0x1;  // set the present bit along with the pfn value
        *((u64*)pud_e) |= 0x10;                          // set the user bit

        if(vma->access_flags == 0x3) {
            *((u64*)pud_e) |= 0x8;                       // set the read/write bit
        }
    }

    // calculate the entry of in the third level of the page table
    u64 pmd_e = ((u64)osmap( ( ( *((u64*)pud_e)  ) >> ADDR_SHIFT) ) ) + (pmdIdx)*(PTE_SIZE);

    // check if page frame has been allocated for the next level of the page table
    if( ( *((u64*)pmd_e) & 1 ) == 0) {
        // allocate pfn for pte_t
        u64 pte_pfn = os_pfn_alloc(OS_PT_REG);
        if(pte_pfn == 0) {
            return -EINVAL;
        }

        // update the pmd_entry
        *((u64*)pmd_e) = (pte_pfn << ADDR_SHIFT) | 0x1;  // set the present bit along with the pfn value
        *((u64*)pmd_e) |= 0x10;                          // set the user bit

        if(vma->access_flags == 0x3) {
            *((u64*)pmd_e) |= 0x8;                       // set the read/write bit
        }
    }

    // calculate the entry of in the final level of the page table
    u64 pte_entry_VA = ((u64)osmap( ( ( *((u64*)pmd_e)  ) >> ADDR_SHIFT) ) ) + (pteIdx)*(PTE_SIZE);

    // check if page frame has been allocated for the final level of the page table
    if( ( *((u64*)pte_entry_VA) & 1 ) == 0) {
        // allocate pfn for pte_t
        u64 user_called_pfn = os_pfn_alloc(USER_REG);
        if(user_called_pfn == 0) {
            return -EINVAL;
        }

        // update the pte_entry
        *((u64*)pte_entry_VA) = (user_called_pfn << ADDR_SHIFT) | 0x1;  // set the present bit along with the pfn value
        *((u64*)pte_entry_VA) |= 0x10;                                  // set the user bit
        if(vma->access_flags == 0x3) {
            *((u64*)pte_entry_VA) |= 0x8;                               // set the read/write bit
        }
        else {
            *((u64*)pte_entry_VA) &= ~(0x8);  
        }

        asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
    }

    return 1;
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
