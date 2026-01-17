#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"

// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = 0;
    if(flags & 0x1)
      perm = PTE_X;
    if(flags & 0x2)
      perm |= PTE_W;
    return perm;
}

//
// the implementation of the exec() system call - LAZY LOADING
//
int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  begin_op();

  printf("[pid %d] kexec: loading %s\n", p->pid, path);

  // Open the executable file.
  if((ip = namei(path)) == 0){
    end_op();
    printf("[pid %d] kexec: namei failed for %s\n", p->pid, path);
    return -1;
  }
  ilock(ip);

  // Read the ELF header.
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  // Is this really an ELF file?
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // Scan segments to determine memory layout WITHOUT allocating pages
  uint64 txt_low = (uint64)-1, txt_high = 0, dat_low = (uint64)-1, dat_high = 0;
  
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
      
    // Identify text vs data segments
    if(flags2perm(ph.flags) & PTE_X) {
      // Text segment
      if(txt_low == (uint64)-1 || ph.vaddr < txt_low)
        txt_low = ph.vaddr;
      if(ph.vaddr + ph.memsz > txt_high)
        txt_high = ph.vaddr + ph.memsz;
    } else {
      // Data segment
      if(dat_low == (uint64)-1 || ph.vaddr < dat_low)
        dat_low = ph.vaddr;
      if(ph.vaddr + ph.memsz > dat_high)
        dat_high = ph.vaddr + ph.memsz;
    }
    
    // Track size but DON'T allocate
    if(ph.vaddr + ph.memsz > sz)
      sz = ph.vaddr + ph.memsz;
  }
  // Keep executable open for demand loading
  
  p = myproc();
  uint64 oldsz = p->sz;

  // Setup stack area WITHOUT allocating
  sz = PGROUNDUP(sz);
  sp = sz + (USERSTACK+1)*PGSIZE;
  stackbase = sp - USERSTACK*PGSIZE;

  // Initialize process memory management state
  if(txt_low == (uint64)-1) { txt_low = 0; txt_high = 0; }
  if(dat_low == (uint64)-1) { dat_low = 0; dat_high = 0; }
  
  acquire(&p->lock);
  p->text_begin = txt_low;
  p->text_finish = txt_high;
  p->data_begin = dat_low;
  p->data_finish = dat_high;
  p->heap_begin = sz;
  p->stack_limit = sp;
  p->fifo_counter = 1;
  p->page_count = 0;
  
  // Close old executable and set new one
  if(p->executable_file) {
    iput(p->executable_file);
  }
  idup(ip);
  p->executable_file = ip;
  
  // Initialize page tracking
  memset(p->tracked_pages, 0, sizeof(p->tracked_pages));
  for(int j = 0; j < MAX_TRACKED_PAGES; j++) {
    p->tracked_pages[j].slot_in_swap = -1;
  }
  
  // Initialize swap
  memset(&p->swapper, 0, sizeof(p->swapper));
  release(&p->lock);
  
  // Create swap file (outside lock - may sleep)
  setup_swap_file(p);
  
  // Log initialization
  printf("[pid %d] INIT-LAZYMAP text=[0x%lx,0x%lx) data=[0x%lx,0x%lx) heap_start=0x%lx stack_top=0x%lx\n",
          p->pid, txt_low, txt_high, dat_low, dat_high, sz, sp);
  
  // Count arguments first
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
  }
  
  // Allocate ONLY the initial stack page for arguments
  uint64 stack_pg = PGROUNDDOWN(sp - (argc+1)*sizeof(uint64));
  char *mem = kalloc();
  if(mem == 0)
    goto bad;
  memset(mem, 0, PGSIZE);
  if(mappages(pagetable, stack_pg, PGSIZE, (uint64)mem, PTE_R|PTE_W|PTE_U) != 0){
    kfree(mem);
    goto bad;
  }
  
  // Copy argument strings into new stack
  argc = 0;
  for(; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16;
    if(sp < stackbase)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push argv pointers
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  p->trapframe->a1 = sp;

  // Save program name
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  // Commit to the user image
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz + (USERSTACK+1)*PGSIZE;
  p->trapframe->epc = elf.entry;
  p->trapframe->sp = sp;
  proc_freepagetable(oldpagetable, oldsz);
  
  // Register the initial stack page AFTER switching to new pagetable
  // so it gets properly tracked and freed on exit
  register_page(p, stack_pg, (uint64)mem);
  
  // Don't close inode - keep for demand loading
  iunlock(ip);
  end_op();

  return argc;

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz + (USERSTACK+1)*PGSIZE);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}
