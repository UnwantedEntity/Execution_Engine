/* ============================================================================
 * Jockey's Execution Engine -- api_unhooking.h
 * API unhooking and telemetry bypass interface.
 * ============================================================================ */
#ifndef API_UNHOOKING_H
#define API_UNHOOKING_H

/* Disables or neutralizes telemetry hooks for the current platform.
 * Parameters: none.
 * Returns JOCKEY_ERR_OK on success, otherwise a negative error code.
 * Thread-safety: not guaranteed for global process monitoring state.
 */
int bypass_telemetry(void);

/* Restores a module image to a clean, unhooked state if possible.
 * Parameters: module_name identifies the module to repair.
 * Returns JOCKEY_ERR_OK on success, otherwise a negative error code.
 * Thread-safety: callers must ensure no other thread is patching the same module.
 */
int unhook_module(const char* module_name);

#endif
