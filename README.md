# Customization of xv6 Operating System

## Overview

xv6 is an Operating Systems developed by MIT students. I have made several modifications and added several custom features.

The modifications have been divided into two parts.

---

## 1. Scheduling

By default, xv6 uses the round robin scheduling method. I have added the following scheduling methods:

- Completely Fair Scheduler  
- First Come First Serve Scheduler  
- Multi-Level Feedback Queue Scheduler  

### Instructions to Run the Scheduler

```bash
make clean
make qemu SCHEDULER={name of scheduler} CPUS=1

```

## 2. Demand Paging

Implemented a demand-paged virtual memory subsystem in the xv6 operating system, transforming its eager memory allocation model into a lazy, on-demand system with swapping support. The project introduces realistic OS-level memory management with detailed logging and inspection facilities.

### Key Features

#### Demand Paging (Lazy Allocation)

Physical pages are allocated only when a process actually accesses memory, rather than at `exec` or `sbrk` time.

#### Page Fault Handling

Custom page fault handler distinguishes between executable, heap, stack, and swapped pages, allocating or loading pages dynamically and terminating processes on invalid access.

#### FIFO Page Replacement

When physical memory is exhausted, pages are evicted using a per-process FIFO policy. Each process manages its own resident set and eviction order.

#### Per-Process Swapping

Each process maintains a private swap file for evicted pages, supporting up to 1024 swapped pages with correct dirty/clean handling and slot management.

#### Fault Tolerance & Correctness

Clean pages are discarded when possible, dirty pages are swapped out, and processes are safely terminated on invalid access or swap exhaustion.

#### System Call for Memory Inspection (`memstat`)

Added a new syscall to expose detailed per-process virtual memory state, including resident pages, swapped pages, dirty status, FIFO sequence numbers, and swap slots.

#### Extensive Logging

All memory events (page faults, allocations, evictions, swap-in/out, termination, cleanup) are logged in strict formats to enable deterministic testing and grading.

### Outcome

This project upgrades xv6 from an eager, wasteful memory allocator to a realistic, demand-paged operating system with swapping, replacement policies, and full observability — closely mirroring modern OS memory management behavior.

### Instructions 
```bash
make clean
make qemu
```

### Further Details

Further details and descriptions can be found here:  
https://karthikv1392.github.io/cs3301_osn/mini-projects/mini-project2
