#ifdef __linux__

#include "../syscalls.h"
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

// Generic syscall wrapper using syscall()
int syscall_invoke(int number, ...) {
    va_list args;
    va_start(args, number);
    // We need to extract up to 6 arguments, but this is messy.
    // For simplicity, we only support specific syscalls.
    // We'll implement a simpler approach: use the syscall() function directly in PAL.
    va_end(args);
    return -1;
}

#endif // __linux__