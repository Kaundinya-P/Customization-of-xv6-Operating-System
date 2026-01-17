# xv6 Scheduler Implementation Report

## Part A - Basic System Call: getreadcount

### A.1: System Call Implementation

Implemented `sys_getreadcount()` system call that tracks and returns the total number of bytes read by the `read()` system call across all processes since boot.

**Implementation Details:**
- Added a global counter variable to track total bytes read
- Modified the `sys_read()` system call to increment this counter with the number of bytes actually read
- Implemented overflow handling by allowing the counter to wrap around to 0 naturally (using unsigned integer overflow)
- The system call returns the current value of the global read counter

**Key Changes:**
- Modified `sys_read()` to update counter after successful read operations
- Implemented `sys_getreadcount()` to return current counter value
- Added system call number and declaration in appropriate header files

### A.2: User Program

Created `readcount.c` user program that demonstrates the functionality:

**Program Flow:**
1. Calls `getreadcount()` and prints the initial value
2. Opens and reads 100 bytes from a file (README)
3. Calls `getreadcount()` again and prints the updated value
4. Verifies that the counter increased by the expected amount

**Verification:**
The program successfully shows the increase in read count after performing file read operations, confirming the system call works correctly.

## Part B - Scheduler Implementations

### Background

Modified xv6's default round-robin scheduler to support three different scheduling policies:
1. Default Round Robin (original)
2. First Come First Serve (FCFS)
3. Completely Fair Scheduler (CFS)

The kernel uses compile-time flags to determine which scheduler to use:
- `make qemu SCHEDULER=FCFS` for First Come First Serve
- `make qemu SCHEDULER=CFS` for Completely Fair Scheduler
- Default compilation uses Round Robin

### B.1: First Come First Serve (FCFS) Implementation

**Key Features:**
- Non-preemptive scheduling policy
- Processes are selected based on creation time (earliest first)
- Once a process starts running, it continues until completion or blocking

**Implementation Details:**
- Added `ctime` field to `struct proc` to store process creation time
- Modified `allocproc()` to set creation time when process is allocated
- Implemented FCFS scheduler logic in `scheduler()` function:
  - Scans all RUNNABLE processes to find the one with earliest creation time
  - Selects and runs that process non-preemptively
  - Process runs until it voluntarily yields, blocks, or terminates

**Code Changes:**
- Extended process control block with timing information
- Used preprocessor directives (`#if ACTIVE_SCHEDULER == SCHED_FCFS`) for conditional compilation
- Added debug output to show scheduling decisions

### B.2: Completely Fair Scheduler (CFS) Implementation

#### B.2.1: Priority Support

**Nice Value Implementation:**
- Added `nice` field to `struct proc` with range [-20, +19]
- Default nice value: 0 (neutral priority)
- Nice -20: Highest priority (weight = ~88761)
- Nice +19: Lowest priority (weight = ~15)

**Weight Calculation:**
- Implemented `compute_process_weight()` function
- Uses approximation: `weight = 1024 / (1.25 ^ nice)`
- For positive nice: iteratively multiply by 4/5 ratio
- For negative nice: iteratively multiply by 5/4 ratio
- Base weight for nice=0: 1024

#### B.2.2: Virtual Runtime Tracking

**vRuntime Implementation:**
- Added `vruntime` field to track virtual runtime per process
- Initialized to 0 when process is created
- Updated on every timer tick using `update_cfs_on_tick()`
- vRuntime increment: `delta = (1024 * PRECISION) / weight`
- Higher weight (lower nice) → slower vruntime growth
- Lower weight (higher nice) → faster vruntime growth

**Update Mechanism:**
- vRuntime updated in timer interrupt handler
- Uses precision scaling factor (1000) for better granularity
- Debug output shows vruntime progression for monitoring

#### B.2.3: Scheduling Logic

**Process Selection:**
- Always schedules the RUNNABLE process with minimum vruntime
- Maintains fairness by ensuring processes with less CPU time (lower vruntime) get priority
- Scans all processes to find minimum vruntime candidate

**Implementation:**
- Two-pass algorithm: count runnable processes, then select minimum vruntime
- Proper lock management during process selection
- Updates process weight based on current nice value before scheduling

#### B.2.4: Time Slice Calculation

**Dynamic Time Slicing:**
- Target latency: 48 ticks
- Time slice calculation: `time_slice = target_latency / number_of_runnable_processes`
- Minimum time slice: 3 ticks (enforced)
- Adapts to system load automatically

**Preemption:**
- Tracks ticks used in current time slice (`slice_ticks_used`)
- Process yields when time slice is exhausted
- Allows other processes with low vruntime to run

### Logging and Debug Output

**CFS Scheduler Logging:**
Implemented comprehensive logging as requested


**Log Information:**
- Process ID (PID) of each runnable process
- Current vRuntime value for each process
- Clear indication of selected process (lowest vRuntime)
- Verification that scheduler selects correct process
- Shows vRuntime updates after each scheduling decision

### Performance Comparison

**Methodology:**
- Configured system to run on single CPU for fair comparison
- Used `schedulertest` command to measure scheduling metrics
- Measured average waiting time and running time for processes

**Scheduler Performance Results:**

| Scheduler | Avg Waiting Time | Avg Running Time | 
|-----------|------------------|------------------|
| Round Robin | Moderate | Balanced | 
| FCFS | High variance | Depends on arrival | 
| CFS | Low variance | Proportional to weight | 

**Analysis:**

1. **Round Robin (Default):**
   - Provides reasonable fairness with fixed time quantum
   - Simple implementation with predictable behavior
   - Good for interactive systems

2. **First Come First Serve (FCFS):**
   - Suffers from convoy effect when long processes arrive first
   - Non-preemptive nature can lead to poor responsiveness
   - Simple but not optimal for most workloads
   - Good for batch processing systems

3. **Completely Fair Scheduler (CFS):**
   - Provides excellent fairness through vruntime mechanism
   - Adapts time slices based on system load
   - Weight-based prioritization allows fine-grained control
   - Best overall performance for mixed workloads
   - Slightly more complex but worth the benefits

### Implementation Challenges and Solutions

1. **Integer Arithmetic for Weight Calculation:**
   - Challenge: Avoiding floating-point arithmetic in kernel
   - Solution: Used iterative integer multiplication with ratios (4/5, 5/4)

2. **vRuntime Precision:**
   - Challenge: Maintaining precision with integer arithmetic
   - Solution: Used scaling factor (CFS_VRUNTIME_PRECISION = 1000)

3. **Lock Management:**
   - Challenge: Proper synchronization during scheduler decisions
   - Solution: Careful acquire/release of process locks with early release optimization

4. **Time Slice Preemption:**
   - Challenge: Ensuring fair preemption without excessive context switches
   - Solution: Dynamic time slice calculation with minimum threshold

### Conclusion

Successfully implemented three different scheduling algorithms in xv6:

- **System Call (getreadcount):** Provides accurate tracking of system-wide read operations
- **FCFS Scheduler:** Simple non-preemptive scheduler suitable for batch systems
- **CFS Scheduler:** Advanced fair scheduler with priority support and dynamic time slicing

### BONUS
   - Implemented the MLFQ bonus scheduler too