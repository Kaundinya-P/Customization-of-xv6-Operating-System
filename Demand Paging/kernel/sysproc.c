#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "memstat.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if(t == SBRK_EAGER || n < 0) {
    if(growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if(addr + n < addr)
      return -1;
    if(addr + n > TRAPFRAME)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_memstat(void)
{
  uint64 addr;
  struct proc *p = myproc();
  struct proc_mem_stat info;
  
  argaddr(0, &addr);
  
  acquire(&p->lock);
  
  info.pid = p->pid;
  info.next_fifo_seq = p->fifo_counter;
  info.num_resident_pages = p->page_count;
  
  // Count swapped pages
  int swap_cnt = 0;
  for(int i = 0; i < SWAP_MAX_PAGES/8; i++) {
    for(int bit = 0; bit < 8; bit++) {
      if(p->swapper.bitmap[i] & (1 << bit)) {
        swap_cnt++;
      }
    }
  }
  info.num_swapped_pages = swap_cnt;
  
  // Calculate total virtual pages
  uint64 min_addr = p->heap_begin;
  if(p->text_begin && (p->text_begin < min_addr)) min_addr = p->text_begin;
  if(p->data_begin && (p->data_begin < min_addr)) min_addr = p->data_begin;
  if(min_addr > p->sz) min_addr = p->sz;
  info.num_pages_total = (p->sz > min_addr) ? ((p->sz - min_addr) / PGSIZE) : 0;
  
  // Fill page information
  int idx = 0;
  
  // Add resident pages
  for(int i = 0; i < p->page_count && idx < MAX_PAGES_INFO; i++) {
    if(p->tracked_pages[i].vaddr != 0) {
      info.pages[idx].va = p->tracked_pages[i].vaddr;
      info.pages[idx].state = RESIDENT;
      info.pages[idx].is_dirty = p->tracked_pages[i].dirty;
      info.pages[idx].seq = p->tracked_pages[i].fifo_seq;
      info.pages[idx].swap_slot = -1;
      idx++;
    }
  }
  
  // Add swapped pages
  for(int i = 0; i < MAX_TRACKED_PAGES && idx < MAX_PAGES_INFO; i++) {
    if(p->tracked_pages[i].slot_in_swap != -1) {
      info.pages[idx].va = p->tracked_pages[i].vaddr;
      info.pages[idx].state = SWAPPED;
      info.pages[idx].is_dirty = 0;
      info.pages[idx].seq = p->tracked_pages[i].fifo_seq;
      info.pages[idx].swap_slot = p->tracked_pages[i].slot_in_swap;
      idx++;
    }
  }
  
  // Fill unmapped pages
  for(uint64 va = PGROUNDDOWN(min_addr); va < p->sz && idx < MAX_PAGES_INFO; va += PGSIZE) {
    int exists = 0;
    for(int j = 0; j < idx; j++) {
      if(info.pages[j].va == PGROUNDDOWN(va)) {
        exists = 1;
        break;
      }
    }
    
    if(!exists) {
      info.pages[idx].va = PGROUNDDOWN(va);
      info.pages[idx].state = UNMAPPED;
      info.pages[idx].is_dirty = 0;
      info.pages[idx].seq = 0;
      info.pages[idx].swap_slot = -1;
      idx++;
    }
  }
  
  release(&p->lock);
  
  if(copyout(p->pagetable, addr, (char*)&info, sizeof(info)) < 0)
    return -1;
    
  return 0;
}
