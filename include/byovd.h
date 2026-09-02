/* ============================================================================
 * Jockey's Execution Engine -- byovd.h
 * Bring Your Own Vulnerable Driver interface.
 * ============================================================================ */
#ifndef BYOVD_H
#define BYOVD_H

#include <stddef.h>
#include <stdint.h>

/* Loads a vulnerable driver from the provided file path.
 * Parameters: driver_path must point to a valid driver image.
 * Returns JOCKEY_ERR_OK or a negative error code.
 * Thread-safety: not guaranteed across concurrent driver operations.
 */
int load_byovd(const char* driver_path);
/* Unloads a previously loaded vulnerable driver.
 * Parameters: driver_name identifies the service name.
 * Returns JOCKEY_ERR_OK or negative error code.
 */
int unload_byovd(const char* driver_name);
/* Disables EDR callback registration through the platform driver path.
 * Returns JOCKEY_ERR_OK or negative error code.
 */
int disable_edr_callbacks(void);

/* Kernel memory read/write (used by pal and other components) */
int read_kernel_memory(uintptr_t address, void* buffer, size_t size);
int write_kernel_memory(uintptr_t address, const void* buffer, size_t size);

#endif
