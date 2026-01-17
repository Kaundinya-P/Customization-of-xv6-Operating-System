#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

#define NFORK 10
#define IO_PROCESSES 5

int main() {
  int n, pid;
  //int start_time, end_time;
  
  printf("Starting scheduler test with %d processes...\n", NFORK);
  printf("IO processes: 0-%d, CPU processes: %d-%d\n", IO_PROCESSES-1, IO_PROCESSES, NFORK-1);
  
  //start_time = uptime();
  
  for (n = 0; n < NFORK; n++) {
    pid = fork();
    if (pid < 0) {
      printf("Fork failed for process %d\n", n);
      break;
    }
    if (pid == 0) {
      // Child process
      int child_start = uptime();
      
      if (n < IO_PROCESSES) {
        // IO-bound process: sleep and do light work
        printf("IO Process %d (PID %d) starting\n", n, getpid());
        for (int round = 0; round < 3; round++) {
          pause(50); // Simulate I/O wait
          printf("IO Process %d woke up (round %d)\n", n, round + 1);
        }
      } else {
        // CPU-bound process: intensive computation
        printf("CPU Process %d (PID %d) starting\n", n, getpid());
        volatile int sum = 0;
        for (volatile int i = 0; i < 100000000; i++) {
          sum += i % 1000;
          if (i % 25000000 == 0 && i > 0) {
            printf("CPU Process %d progress: %d%%\n", n, (i * 100) / 100000000);
          }
        }
      }
      
      int child_end = uptime();
      printf("Process %d (PID %d) finished in %d ticks\n", n, getpid(), child_end - child_start);
      exit(0);
    }
  }
  
  // Parent waits for all children
  printf("Parent waiting for all children...\n");
  for (n = 0; n < NFORK; n++) {
    wait(0);
  }
  
  //end_time = uptime();
  printf("Scheduler test finished!\n");
  exit(0);
}
