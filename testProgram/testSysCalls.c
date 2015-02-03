/* Test system calls for Project 2
*/
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

// These values MUST match the unistd_32.h modifications:
#define __NR_cs3013_syscall1 355
#define __NR_cs3013_syscall2 356
#define __NR_cs3013_syscall3 357

long testCall1 ( void) {
	return (long) syscall(__NR_cs3013_syscall1);
}
long testCall2 ( void) {
	return (long) syscall(__NR_cs3013_syscall2);
}
long testCall3 ( void) {
	return (long) syscall(__NR_cs3013_syscall3);
}

// Main test program
#define MAX_ARGS 32
int main(int argc, const char* argv[]){
	printf("Testing system calls...!\n");
	printf("The return values of the system calls are:\n");
	printf("\tcs3013_syscall1: %ld\n", testCall1());
	//printf("\tcs3013_syscall2: %ld\n", testCall2());
	//printf("\tcs3013_syscall3: %ld\n", testCall3());

	return 0;
}