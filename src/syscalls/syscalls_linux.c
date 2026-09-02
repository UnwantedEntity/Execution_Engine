/* ============================================================================
 * Jockey's Execution Engine -- syscalls_linux.c
 * Linux syscall dispatcher stub. Syscalls injected via ptrace in PAL.
 * ============================================================================ */

#ifdef __linux__

#include "syscalls.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <errno.h>

int syscall_invoke(int number, ...) {
    (void)number;
    /* Linux uses remote_syscall() in pal_linux.c instead */
    return -1;
}

#endif /* __linux__ */
