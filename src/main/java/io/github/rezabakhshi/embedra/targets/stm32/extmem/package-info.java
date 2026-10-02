/**
 * Pure STM32 external-memory mapping and loading for exact curated parts.
 *
 * <p>An external-memory plan pairs the validated T039 {@code Stm32MemoryPlanner.Plan}
 * with one confirmed board fact source: the digest-pinned T042 board profile, or
 * an explicitly confirmed user-supplied custom profile. It models each controller
 * window (the CPU-mapped aperture of an OCTOSPI/XSPI/QUADSPI/FMC controller) as
 * separate from the external device's own extent, plans external loads against
 * that separation, and fails closed with stable diagnostics on a mismatched part,
 * an unavailable profile, a window that collides with a pinned MCU region or
 * another window, an unrecognized controller, or an out-of-range load. No
 * device, controller, window, alias, size, permission, board link, or address
 * is ever invented, every part keeps its {@code PLANNED} support state, and no
 * Ghidra mutation is performed in this package (STM-009, STM-016, STM-019).
 */
package io.github.rezabakhshi.embedra.targets.stm32.extmem;
