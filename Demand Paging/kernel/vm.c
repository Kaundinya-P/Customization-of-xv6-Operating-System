#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "proc.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "stat.h"

/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x4000000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // allocate and map a kernel stack for each process.
  proc_mapstacks(kpgtbl);
  
  return kpgtbl;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Initialize the kernel_pagetable, shared by all CPUs.
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch the current CPU's h/w page table register to
// the kernel's page table, and enable paging.
void
kvminithart()
{
  // wait for any previous writes to the page table memory to finish.
  sfence_vma();

  w_satp(MAKE_SATP(kernel_pagetable));

  // flush stale entries from the TLB.
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa.
// va and size MUST be page-aligned.
// Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("mappages: va not aligned");

  if((size % PGSIZE) != 0)
    panic("mappages: size not aligned");

  if(size == 0)
    panic("mappages: size");
  
  a = va;
  last = va + size - PGSIZE;
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Remove npages of mappings starting from va. va must be
// page-aligned. It's OK if the mappings don't exist.
// Optionally free the physical memory.
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;
  struct proc *p = myproc();

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0) // leaf page table entry allocated?
      continue;   
    if((*pte & PTE_V) == 0)  // has physical page been allocated?
      continue;
    if(do_free){
      uint64 pa = PTE2PA(*pte);
      kfree((void*)pa);
    }
    *pte = 0;
    // Unregister page from tracking if this is a user process
    if(p && p->pagetable == pagetable) {
      unregister_page(p, a);
    }
  }
}

// Allocate PTEs and physical memory to grow a process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz, int xperm)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_R|PTE_U|xperm) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    // Don't register eagerly allocated pages - they don't use demand paging
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
    // uvmunmap already calls unregister_page for each unmapped page
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    } else if(pte & PTE_V){
      panic("freewalk: leaf");
    }
  }
  kfree((void*)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      continue;   // page table entry hasn't been allocated
    if((*pte & PTE_V) == 0)
      continue;   // physical page hasn't been allocated
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto err;
    memmove(mem, (char*)pa, PGSIZE);
    if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
      kfree(mem);
      goto err;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  
  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;
  pte_t *pte;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    if(va0 >= MAXVA)
      return -1;
  
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 0, 0)) == 0) {
        return -1;
      }
    }

    pte = walk(pagetable, va0, 0);
    // forbid copyout over read-only user text pages.
    if((*pte & PTE_W) == 0)
      return -1;
      
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 0, 0)) == 0) {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if(n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;

  while(got_null == 0 && max > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 0, 0)) == 0) {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if(n > max)
      n = max;

    char *p = (char *) (pa0 + (srcva - va0));
    while(n > 0){
      if(*p == '\0'){
        *dst = '\0';
        got_null = 1;
        break;
      } else {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if(got_null){
    return 0;
  } else {
    return -1;
  }
}

// Handle page fault - full demand paging implementation
// write_fault: 1 for write, 0 for read
// terminate: 1 to kill on invalid access, 0 to just return error
uint64
vmfault(pagetable_t pagetable, uint64 va, int write_fault, int terminate)
{
  struct proc *p = myproc();
  uint64 phys_addr;
  char *fault_type;
  char *page_source;
  
  va = PGROUNDDOWN(va);
  
  // Check bounds - user pages must be below TRAPFRAME
  if(va >= TRAPFRAME) {
    if(terminate) {
      fault_type = write_fault ? "write" : "read";
      printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=invalid\n", p->pid, va, fault_type);
      printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", p->pid, va, fault_type);
      setkilled(p);
    }
    return 0;
  }
  
  // Check if already resident
  pte_t *pte_check = walk(pagetable, va, 0);
  if(pte_check && (*pte_check & PTE_V) && (*pte_check & PTE_U)) {
    // Page is present - handle write to read-only page (dirty tracking)
    if(write_fault && ((*pte_check & PTE_W) == 0)) {
      fault_type = "write";
      // Check if this page should be writable
      int should_be_writable = 0;
      if(va >= p->heap_begin && va < p->sz - (USERSTACK+1)*PGSIZE) {
        page_source = "heap";
        should_be_writable = 1;
      } else if(va >= p->sz - USERSTACK*PGSIZE && va < p->stack_limit) {
        page_source = "stack";
        should_be_writable = 1;
      } else if(va >= p->data_begin && va < p->data_finish) {
        page_source = "data";
        should_be_writable = 1;
      } else if(va >= p->text_begin && va < p->text_finish) {
        page_source = "text";
        should_be_writable = 0;
      } else {
        page_source = "exec";
      }
      
      if(should_be_writable) {
        printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, fault_type, page_source);
        // Grant write permission and mark dirty
        *pte_check |= PTE_W;
        sfence_vma();
        set_page_dirty(p, va);
        return PTE2PA(*pte_check);
      } else {
        // Write to read-only page (e.g., text segment)
        printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=invalid\n", p->pid, va, fault_type);
        if(terminate) {
          printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", p->pid, va, fault_type);
          setkilled(p);
        }
        return 0;
      }
    }
    return PTE2PA(*pte_check);
  }
  
  // Check if page was swapped
  int swap_slot = locate_swapped(p, va);
  if(swap_slot != -1) {
    page_source = "swap";
    fault_type = write_fault ? "write" : "read";
    
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, fault_type, page_source);
    
    phys_addr = (uint64) kalloc();
    if(phys_addr == 0) {
      printf("[pid %d] MEMFULL\n", p->pid);
      if(evict_fifo_page(p))
        phys_addr = (uint64) kalloc();
      if(phys_addr == 0)
        return 0;
    }
    
    if(read_from_swap(p, va, swap_slot, phys_addr) != 0) {
      kfree((void*)phys_addr);
      return 0;
    }
    
    int perms = PTE_R | PTE_U;
    if(va >= p->data_begin && va < p->data_finish) {
      perms |= PTE_W;
    } else if(va >= p->heap_begin) {
      perms |= PTE_W;
    }
    
    if(mappages(p->pagetable, va, PGSIZE, phys_addr, perms) != 0) {
      kfree((void*)phys_addr);
      return 0;
    }
    
    register_page(p, va, phys_addr);
    printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, p->fifo_counter - 1);
    return phys_addr;
  }
  
  // Determine fault type and validate
  fault_type = write_fault ? "write" : "read";
  
  // Handle uninitialized process (fork without exec)
  if(p->text_begin == 0 && p->text_finish == 0 && p->data_begin == 0 && p->data_finish == 0 && p->heap_begin == 0) {
    if(va >= p->sz - (USERSTACK+1)*PGSIZE && va < p->sz) {
      page_source = "stack";
      printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, fault_type, page_source);
      phys_addr = allocate_page_lazy(p, va, PTE_R | PTE_W | PTE_U);
      if(phys_addr == 0) return 0;
      printf("[pid %d] ALLOC va=0x%lx\n", p->pid, va);
    } else {
      printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=invalid\n", p->pid, va, fault_type);
      printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", p->pid, va, fault_type);
      setkilled(p);
      return 0;
    }
  } else if(p->text_finish > p->text_begin && va >= p->text_begin && va < p->text_finish) {
    page_source = "exec";
    fault_type = "exec";
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, fault_type, page_source);
    phys_addr = load_from_exec(p, va, PTE_R | PTE_X | PTE_U);
    if(phys_addr == 0) return 0;
    printf("[pid %d] LOADEXEC va=0x%lx\n", p->pid, va);
  } else if(p->data_finish > p->data_begin && va >= p->data_begin && va < p->data_finish) {
    page_source = "exec";
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, fault_type, page_source);
    phys_addr = load_from_exec(p, va, PTE_R | PTE_W | PTE_U);
    if(phys_addr == 0) return 0;
    printf("[pid %d] LOADEXEC va=0x%lx\n", p->pid, va);
  } else if(va >= p->heap_begin && va < p->sz - (USERSTACK+1)*PGSIZE) {
    page_source = "heap";
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, fault_type, page_source);
    phys_addr = allocate_page_lazy(p, va, PTE_R | PTE_W | PTE_U);
    if(phys_addr == 0) return 0;
    printf("[pid %d] ALLOC va=0x%lx\n", p->pid, va);
  } else if(va >= p->sz - USERSTACK*PGSIZE && va >= PGROUNDDOWN(p->trapframe->sp - PGSIZE) && va < p->stack_limit) {
    page_source = "stack";
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, fault_type, page_source);
    phys_addr = allocate_page_lazy(p, va, PTE_R | PTE_W | PTE_U);
    if(phys_addr == 0) return 0;
    printf("[pid %d] ALLOC va=0x%lx\n", p->pid, va);
  } else {
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=invalid\n", p->pid, va, fault_type);
    if(terminate) {
      printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", p->pid, va, fault_type);
      setkilled(p);
    }
    return 0;
  }
  
  register_page(p, va, phys_addr);
  if(write_fault) {
    set_page_dirty(p, va);
  }
  printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, p->fifo_counter - 1);
  return phys_addr;
}

int
ismapped(pagetable_t pagetable, uint64 va)
{
  pte_t *pte = walk(pagetable, va, 0);
  if (pte == 0) {
    return 0;
  }
  if (*pte & PTE_V){
    return 1;
  }
  return 0;
}

// Allocate a zero-filled page
uint64
allocate_page_lazy(struct proc *p, uint64 va, int permissions)
{
  uint64 mem = (uint64) kalloc();
  if(mem == 0) {
    printf("[pid %d] MEMFULL\n", p->pid);
    if(evict_fifo_page(p))
      mem = (uint64) kalloc();
    if(mem == 0)
      return 0;
  }
  
  memset((void*)mem, 0, PGSIZE);
  
  if(mappages(p->pagetable, va, PGSIZE, mem, permissions) != 0) {
    kfree((void*)mem);
    return 0;
  }
  
  return mem;
}

// Load page from executable file
uint64
load_from_exec(struct proc *p, uint64 va, int permissions)
{
  uint64 mem;
  struct inode *ip = p->executable_file;
  struct elfhdr hdr;
  struct proghdr segment;
  int i, offset;
  
  if(ip == 0) return 0;
  
  mem = (uint64) kalloc();
  if(mem == 0) {
    printf("[pid %d] MEMFULL\n", p->pid);
    if(evict_fifo_page(p))
      mem = (uint64) kalloc();
    if(mem == 0)
      return 0;
  }
  
  memset((void*)mem, 0, PGSIZE);
  
  ilock(ip);
  if(readi(ip, 0, (uint64)&hdr, 0, sizeof(hdr)) != sizeof(hdr)) {
    iunlock(ip);
    kfree((void*)mem);
    return 0;
  }
  
  // Find segment containing this VA
  for(i = 0, offset = hdr.phoff; i < hdr.phnum; i++, offset += sizeof(segment)) {
    if(readi(ip, 0, (uint64)&segment, offset, sizeof(segment)) != sizeof(segment)) {
      iunlock(ip);
      kfree((void*)mem);
      return 0;
    }
    
    if(segment.type != ELF_PROG_LOAD)
      continue;
      
    if(va >= segment.vaddr && va < segment.vaddr + segment.memsz) {
      uint64 page_begin = PGROUNDDOWN(va);
      uint64 file_end = segment.vaddr + segment.filesz;
      
      if(page_begin < file_end) {
        uint64 read_start = page_begin;
        uint64 read_end = page_begin + PGSIZE;
        
        if(read_start < segment.vaddr) read_start = segment.vaddr;
        if(read_end > file_end) read_end = file_end;
        
        if(read_end > read_start) {
          uint64 file_off = segment.off + (read_start - segment.vaddr);
          uint64 mem_off = read_start - page_begin;
          uint64 count = read_end - read_start;
          
          if(readi(ip, 0, mem + mem_off, file_off, count) != count) {
            iunlock(ip);
            kfree((void*)mem);
            return 0;
          }
        }
      }
      break;
    }
  }
  
  iunlock(ip);
  
  if(mappages(p->pagetable, va, PGSIZE, mem, permissions) != 0) {
    kfree((void*)mem);
    return 0;
  }
  
  return mem;
}

// Register page in FIFO tracking
void
register_page(struct proc *p, uint64 va, uint64 pa)
{
  acquire(&p->lock);
  
  int slot = -1;
  for(int i = 0; i < MAX_TRACKED_PAGES; i++) {
    if(p->tracked_pages[i].vaddr == 0 && p->tracked_pages[i].slot_in_swap == -1) {
      slot = i;
      break;
    }
  }
  
  if(slot == -1) {
    if(p->page_count < MAX_TRACKED_PAGES) {
      slot = p->page_count;
    } else {
      // Tracking array is full - skip registration
      // Page is still allocated and usable, just not tracked for eviction
      release(&p->lock);
      return;
    }
  }
  
  p->tracked_pages[slot].vaddr = va;
  p->tracked_pages[slot].fifo_seq = p->fifo_counter++;
  p->tracked_pages[slot].dirty = 0;
  p->tracked_pages[slot].slot_in_swap = -1;
  
  if(slot >= p->page_count) {
    p->page_count = slot + 1;
  }
  
  release(&p->lock);
}

// FIFO page eviction
int
evict_fifo_page(struct proc *p)
{
  acquire(&p->lock);
  
  int victim_idx = -1;
  int min_seq = -1;
  
  for(int i = 0; i < p->page_count; i++) {
    if(p->tracked_pages[i].vaddr != 0) {
      if(victim_idx == -1 || p->tracked_pages[i].fifo_seq < min_seq) {
        victim_idx = i;
        min_seq = p->tracked_pages[i].fifo_seq;
      }
    }
  }
  
  if(victim_idx == -1) {
    release(&p->lock);
    return 0;
  }
  
  uint64 victim_va = p->tracked_pages[victim_idx].vaddr;
  int victim_seq = p->tracked_pages[victim_idx].fifo_seq;
  int is_dirty = p->tracked_pages[victim_idx].dirty;
  
  printf("[pid %d] VICTIM va=0x%lx seq=%d algo=FIFO\n", p->pid, victim_va, victim_seq);
  
  pte_t *pte = walk(p->pagetable, victim_va, 0);
  if(pte == 0 || (*pte & PTE_V) == 0) {
    release(&p->lock);
    return 0;
  }
  
  uint64 pa = PTE2PA(*pte);
  
  if(is_dirty) {
    printf("[pid %d] EVICT va=0x%lx state=dirty\n", p->pid, victim_va);
    release(&p->lock);
    int slot = write_to_swap(p, victim_va, pa);
    if(slot == -1)
      return 0;
    acquire(&p->lock);
    *pte = 0;
    p->tracked_pages[victim_idx].slot_in_swap = slot;
    p->tracked_pages[victim_idx].dirty = 0;
    release(&p->lock);
    kfree((void*)pa);
  } else {
    printf("[pid %d] EVICT va=0x%lx state=clean\n", p->pid, victim_va);
    printf("[pid %d] DISCARD va=0x%lx\n", p->pid, victim_va);
    *pte = 0;
    p->tracked_pages[victim_idx].dirty = 0;
    release(&p->lock);
    kfree((void*)pa);
  }
  
  return 1;
}

// Mark page dirty
void
set_page_dirty(struct proc *p, uint64 va)
{
  acquire(&p->lock);
  for(int i = 0; i < p->page_count; i++) {
    if(p->tracked_pages[i].vaddr == va) {
      p->tracked_pages[i].dirty = 1;
      break;
    }
  }
  release(&p->lock);
}

// Unregister page from FIFO tracking
void
unregister_page(struct proc *p, uint64 va)
{
  acquire(&p->lock);
  va = PGROUNDDOWN(va);
  for(int i = 0; i < p->page_count; i++) {
    if(p->tracked_pages[i].vaddr == va) {
      p->tracked_pages[i].vaddr = 0;
      p->tracked_pages[i].dirty = 0;
      p->tracked_pages[i].slot_in_swap = -1;
      break;
    }
  }
  release(&p->lock);
}

// Create swap file
void
setup_swap_file(struct proc *p)
{
  char path[32];
  safestrcpy(path, "/pgswp00000", sizeof(path));
  int pid = p->pid;
  for(int i = 0; i < 5; i++) {
    path[11 - i] = '0' + (pid % 10);
    pid /= 10;
  }
  
  begin_op();
  char fname[DIRSIZ];
  struct inode *dir = nameiparent(path, fname);
  if(dir) {
    ilock(dir);
    uint off;
    struct inode *ip = dirlookup(dir, fname, &off);
    if(ip) {
      ilock(ip);
      itrunc(ip);
      iunlock(ip);
    } else {
      ip = ialloc(ROOTDEV, T_FILE);
      if(ip) {
        ilock(ip);
        ip->nlink = 1;
        iupdate(ip);
        if(dirlink(dir, fname, ip->inum) < 0) {
        }
        iunlock(ip);
      }
    }
    iunlock(dir);
    p->swap_file = ip;
  } else {
    p->swap_file = 0;
  }
  end_op();
  
  p->swapper.next_free_slot = 0;
  memset(p->swapper.bitmap, 0, sizeof(p->swapper.bitmap));
}

// Remove swap file
void
remove_swap_file(struct proc *p)
{
  char path[32];
  safestrcpy(path, "/pgswp00000", sizeof(path));
  int pid = p->pid;
  for(int i = 0; i < 5; i++) {
    path[11 - i] = '0' + (pid % 10);
    pid /= 10;
  }
  
  begin_op();
  char fname[DIRSIZ];
  struct inode *dir = nameiparent(path, fname);
  if(dir) {
    ilock(dir);
    uint off;
    struct inode *ip = dirlookup(dir, fname, &off);
    if(ip) {
      ilock(ip);
      struct dirent de;
      memset(&de, 0, sizeof(de));
      writei(dir, 0, (uint64)&de, off, sizeof(de));
      if(ip->nlink > 0) {
        ip->nlink--;
        iupdate(ip);
      }
      iunlockput(ip);
    }
    iunlockput(dir);
  }
  end_op();
}

// Write page to swap
int
write_to_swap(struct proc *p, uint64 va, uint64 pa)
{
  int slot = get_free_slot(p);
  if(slot == -1) {
    printf("[pid %d] SWAPFULL\n", p->pid);
    printf("[pid %d] KILL swap-exhausted\n", p->pid);
    setkilled(p);
    return -1;
  }
  
  int byte_idx = slot / 8;
  int bit_idx = slot % 8;
  p->swapper.bitmap[byte_idx] |= (1 << bit_idx);
  
  if(p->swap_file) {
    begin_op();
    ilock(p->swap_file);
    writei(p->swap_file, 0, pa, slot * PGSIZE, PGSIZE);
    iunlock(p->swap_file);
    end_op();
  }
  
  printf("[pid %d] SWAPOUT va=0x%lx slot=%d\n", p->pid, va, slot);
  return slot;
}

// Read page from swap
int
read_from_swap(struct proc *p, uint64 va, int slot, uint64 pa)
{
  if(p->swap_file) {
    begin_op();
    ilock(p->swap_file);
    readi(p->swap_file, 0, pa, slot * PGSIZE, PGSIZE);
    iunlock(p->swap_file);
    end_op();
  }
  
  int byte_idx = slot / 8;
  int bit_idx = slot % 8;
  p->swapper.bitmap[byte_idx] &= ~(1 << bit_idx);
  
  printf("[pid %d] SWAPIN va=0x%lx slot=%d\n", p->pid, va, slot);
  return 0;
}

// Find free swap slot
int
get_free_slot(struct proc *p)
{
  for(int byte = 0; byte < SWAP_MAX_PAGES/8; byte++) {
    if(p->swapper.bitmap[byte] != 0xFF) {
      for(int bit = 0; bit < 8; bit++) {
        if((p->swapper.bitmap[byte] & (1 << bit)) == 0) {
          return byte * 8 + bit;
        }
      }
    }
  }
  return -1;
}

// Locate swapped page
int
locate_swapped(struct proc *p, uint64 va)
{
  for(int i = 0; i < MAX_TRACKED_PAGES; i++) {
    if(p->tracked_pages[i].vaddr == va && p->tracked_pages[i].slot_in_swap != -1) {
      int slot = p->tracked_pages[i].slot_in_swap;
      p->tracked_pages[i].vaddr = 0;
      p->tracked_pages[i].slot_in_swap = -1;
      return slot;
    }
  }
  return -1;
}