#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main() {
  printf("Scheduler Information:\n");
  printf("======================\n");
  
#ifdef SCHEDULER
  #if SCHEDULER == 1
    printf("Active Scheduler: FCFS (First Come First Serve)\n");
    printf("Features: Non-preemptive, schedules by creation time\n");
  #elif SCHEDULER == 2
    printf("Active Scheduler: CFS (Completely Fair Scheduler)\n");
    printf("Features: Preemptive, nice values, vruntime tracking\n");
    printf("Target latency: 48 ticks\n");
    printf("Min time slice: 3 ticks\n");
    printf("Weight calculation: 1024 / (1.25 ^ nice)\n");
  #else
    printf("Active Scheduler: Round Robin (RR)\n");
    printf("Features: Preemptive, simple round-robin\n");
  #endif
#else
  printf("Active Scheduler: Round Robin (RR) - default\n");
#endif

  printf("\nTo see process details, press Ctrl+P in xv6 console\n");
  printf("(Note: Use external terminal if Ctrl+P opens VS Code search)\n");
  
  exit(0);
}
