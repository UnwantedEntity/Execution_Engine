/* ============================================================================
 * Jockey's Execution Engine -- syscalls.h
 * Syscall number definitions. Platform-specific wrappers in pal.
 * ============================================================================ */
#ifndef SYSCALLS_H
#define SYSCALLS_H

#define SYS_READ    0
#define SYS_WRITE   1
#define SYS_OPEN    2
#define SYS_CLOSE   3
#define SYS_MMAP    9
#define SYS_MUNMAP  11
#define SYS_EXECVE  59
#define SYS_CLONE   56
#define SYS_PTRACE  101

#ifdef __cplusplus
extern "C" {
#endif

/* Generic syscall dispatcher (platform-specific implementations).
 * Parameters: number identifies the target syscall and the remaining arguments are
 * platform-specific; this function is not intended for direct application code.
 * Returns JOCKEY_ERR_OK on success, otherwise a negative error code.
 */
int syscall_invoke(int number, ...);

#ifdef __cplusplus
}
#endif

#endif
