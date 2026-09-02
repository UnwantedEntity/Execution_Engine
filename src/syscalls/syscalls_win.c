/* ============================================================================
 * Jockey's Execution Engine -- syscalls_win.c
 * Windows syscall dispatcher stub. NTDLL functions used directly in PAL.
 * ============================================================================ */

#ifdef _WIN32

#include "syscalls.h"
#include <windows.h>
#include <stdarg.h>

int syscall_invoke(int number, ...) {
    (void)number;
    /* Windows uses NTDLL direct calls via pal_win.c instead */
    return -1;
}

#endif /* _WIN32 */
