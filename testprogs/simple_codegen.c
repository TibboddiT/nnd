// Build: testprogs/build.sh simple_codegen.c
// In nnd, break on ready and jit_called:
//  * At ready(1), use g on the printed code address and code+1. They should reuse
//    a memory tab; Enter sets a raw breakpoint, selectable in the breakpoints pane.
//    Step into multiply: source stepping should stop in generated code.
//  * Scroll towards the end of the memory tab: its range should grow without
//    opening another tab or moving the selected instruction.
//  * At jit_called, select its generated caller. Its return address is a boundary;
//    return-address-minus-one is not. Ambiguous preceding code may be omitted.
//  * Remove instruction breakpoints before ready(2). The code has been rewritten:
//    step into multiply again and check the new lea/ret boundaries in the same tab.
//  * g on the printed hole should fail; g on the adjacent code should still work.
//    Run with "bad" to fault in the hole from the generated caller. Select the
//    caller frame: the failed automatic read must not suppress its readable code.

#define _DEFAULT_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// Function pointer type for our dynamically created function
typedef int (*MulFunc)(int);

__attribute__((noinline)) void ready(int phase) {
    printf("ready %d\n", phase);
}

__attribute__((noinline)) void jit_called(void) {
    puts("inside generated caller");
}

int main(int argc, char **argv) {
    // Machine code for a function that multiplies its argument by 2
    // This is x64 assembly: mov eax, edi; add eax, eax; ret
    unsigned char code[] = {0x89, 0xf8, 0x01, 0xc0, 0xc3};
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t code_size = 256 * 1024;

    // Allocate executable memory using mmap
    void *allocation = mmap(NULL, code_size + 2 * page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (allocation == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    unsigned char *mem = (unsigned char *)allocation + page_size;
    if (munmap(allocation, page_size) || munmap(mem + code_size, page_size)) {
        perror("munmap");
        exit(1);
    }
    printf("code: %p, caller: %p, hole: %p\n", (void *)mem, (void *)(mem + page_size), allocation);
    fflush(stdout);

    // Copy our machine code to the allocated memory
    memset(mem, 0x90, code_size);
    memcpy(mem, code, sizeof(code));

    // Frame-pointer-backed JIT caller: push rbp; mov rbp,rsp; movabs rax,callback;
    // call rax; pop rbp; ret. The callback lets nnd unwind into a symbol-less caller.
    unsigned char caller[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0xb8,
                             0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xd0, 0x5d, 0xc3};
    uintptr_t callback = argc > 1 && !strcmp(argv[1], "bad") ? (uintptr_t)allocation : (uintptr_t)jit_called;
    memcpy(caller + 6, &callback, sizeof(callback));
    memcpy(mem + page_size, caller, sizeof(caller));
    if (mprotect(mem, code_size, PROT_READ | PROT_EXEC)) {
        perror("mprotect");
        exit(1);
    }

    // Cast the memory to our function pointer type
    MulFunc multiply = (MulFunc)mem;

    // Test our function
    ready(1);
    int result = multiply(5);
    printf("5 * 2 = %d\n", result);
    ((void (*)(void))(mem + page_size))();

    if (mprotect(mem, code_size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
        perror("mprotect");
        exit(1);
    }
    // lea eax,[rdi+rdi*2]; ret. The ret is now inside an old instruction.
    unsigned char replacement[] = {0x8d, 0x04, 0x7f, 0xc3};
    memcpy(mem, replacement, sizeof(replacement));
    if (mprotect(mem, code_size, PROT_READ | PROT_EXEC)) {
        perror("mprotect");
        exit(1);
    }
    ready(2);
    printf("5 * 3 = %d\n", multiply(5));

    // Clean up
    if (munmap(mem, code_size) == -1) {
        perror("munmap");
        exit(1);
    }

    return 0;
}
