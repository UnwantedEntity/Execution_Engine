/* ============================================================================
 * Jockey's Execution Engine -- pal.h
 * Platform Abstraction Layer. Cross-platform process/memory/thread ops.
 * ============================================================================ */
#ifndef PAL_H
#define PAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JOCKEY_ERR_OK            0
#define JOCKEY_ERR_GENERIC       -1
#define JOCKEY_ERR_INVALID_PARAM -2
#define JOCKEY_ERR_MEMORY_ALLOC  -3
#define JOCKEY_ERR_OS_API        -4
#define JOCKEY_ERR_DRIVER_LOAD   -5

#ifndef ENABLE_LOGGING
#define ENABLE_LOGGING 1
#endif

#if defined(ENABLE_LOGGING) && ENABLE_LOGGING
#define LOG_ERROR(...)   do { fprintf(stderr, "[JOCKEY][ERROR] " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#define LOG_WARN(...)    do { fprintf(stderr, "[JOCKEY][WARN] " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#define LOG_INFO(...)    do { fprintf(stdout, "[JOCKEY][INFO] " __VA_ARGS__); fprintf(stdout, "\n"); } while (0)
#define LOG_DEBUG(...)   do { fprintf(stdout, "[JOCKEY][DEBUG] " __VA_ARGS__); fprintf(stdout, "\n"); } while (0)
#else
#define LOG_ERROR(...)   do { (void)0; } while (0)
#define LOG_WARN(...)    do { (void)0; } while (0)
#define LOG_INFO(...)    do { (void)0; } while (0)
#define LOG_DEBUG(...)   do { (void)0; } while (0)
#endif

typedef struct PalProcess PalProcess;

/* Protection flags for pal_allocate_memory_remote / pal_protect_memory_remote */
#define PAL_PROT_EXECUTE        0x01
#define PAL_PROT_READ           0x02
#define PAL_PROT_WRITE          0x04
#define PAL_PROT_READWRITE      (PAL_PROT_READ | PAL_PROT_WRITE)
#define PAL_PROT_EXECUTE_READ   (PAL_PROT_EXECUTE | PAL_PROT_READ)
#define PAL_PROT_RWX            (PAL_PROT_EXECUTE | PAL_PROT_READ | PAL_PROT_WRITE)

/* Process management */
/* Creates a suspended process and returns a tracked PalProcess handle. */
int pal_create_process_suspended(const char* image_path, PalProcess** out);
/* Resumes a suspended process. Returns JOCKEY_ERR_OK on success. */
int pal_resume_process(PalProcess* proc);
/* Terminates a process and releases process-specific resources. */
int pal_terminate_process(PalProcess* proc);
/* Blocks until the target process exits. */
int pal_wait_for_process(PalProcess* proc);
/* Releases all allocations tracked by the process wrapper. */
void pal_close_process(PalProcess* proc);
/* Returns the process identifier or 0 if the handle is invalid. */
uint32_t pal_get_pid(PalProcess* proc);

/* Remote memory operations */
/* Reserves and commits remote memory in the target process. */
void* pal_allocate_memory_remote(PalProcess* proc, size_t size, int protection);
/* Writes size bytes to a remote address. */
int pal_write_memory_remote(PalProcess* proc, void* dest, const void* src, size_t size);
/* Reads size bytes from a remote address. */
int pal_read_memory_remote(PalProcess* proc, const void* src, void* dest, size_t size);
/* Updates remote page protection. */
int pal_protect_memory_remote(PalProcess* proc, void* addr, size_t size, int protection);
/* Releases remote memory previously allocated by pal_allocate_memory_remote. */
int pal_free_memory_remote(PalProcess* proc, void* addr);

/* Remote thread operations */
/* Creates a remote thread that begins execution at start_routine. */
int pal_create_remote_thread(PalProcess* proc, void* start_routine, void* arg);
/* Fills a thread context structure for the target process or thread. */
int pal_get_thread_context(PalProcess* proc, void* context);
/* Applies a thread context structure to the target thread. */
int pal_set_thread_context(PalProcess* proc, const void* context);

/* Direct syscall control (Windows only; Linux always uses ptrace) */
void pal_set_use_direct_syscalls(int flag);

/* Kernel / Driver operations (BYOVD) */
/* Loads a kernel driver or platform equivalent. */
int pal_load_driver(const char* driver_path);
/* Unloads a previously loaded driver. */
int pal_unload_driver(const char* driver_name);
/* Reads kernel memory into buffer. */
int pal_read_kernel_memory(uintptr_t address, void* buffer, size_t size);
/* Writes buffer contents to kernel memory. */
int pal_write_kernel_memory(uintptr_t address, const void* buffer, size_t size);

/* API unhooking & telemetry bypass */
/* Restores a module to a clean state by undoing inline hooks. */
int pal_unhook_module(const char* module_name);
/* Disables telemetry or monitoring hooks relevant to the host OS. */
int pal_bypass_telemetry(void);

/* Linux-specific: remote dlopen (for reflective injection) */
/* Loads a shared object in the target process via remote dlopen. */
int pal_remote_dlopen(PalProcess* proc, const void* so_data, size_t so_size);

/* Direct syscall wrappers (Windows syscall-only mode) */
/* Opens a process handle using direct syscall paths when enabled. */
int pal_syscall_open_process(uint32_t pid, int access, PalProcess** out);
/* Allocates remote memory through syscall-based paths. */
int pal_syscall_allocate_memory(PalProcess* proc, void** addr, size_t size, int protection);
/* Writes to a previously allocated remote memory region using syscall-based paths. */
int pal_syscall_write_memory(PalProcess* proc, void* dest, const void* src, size_t size);

#ifdef __cplusplus
}
#endif

#endif
