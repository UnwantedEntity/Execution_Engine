#ifdef _WIN32

#include "../syscalls.h"
#include <windows.h>
#include <stdio.h>

int syscall_invoke(int number, ...) {
    // Not used on Windows; we rely on ntdll functions.
    (void)number;
    return -1;
}

#endif // _WIN32