/**
 * Pure STM32 dual-core/heterogeneous workspace planning for exact curated parts.
 *
 * <p>A workspace plan references the validated T039 {@code Stm32MemoryPlanner.Plan}
 * and the T044 security record for the same exact part without mutating either.
 * It assigns one program slot per independently supplied executable domain,
 * attributes shared versus private memory only from pinned {@code sharedAccess}
 * facts, reuses the pinned IPCC mailbox and HSEM semaphore register windows and
 * the pinned release-from-reset boot order, and emits typed cross-program
 * references with provenance so an analyst can navigate core programs without
 * inventing a second flash image or duplicating physical RAM (STM-011,
 * STM-020, TOPO-002..TOPO-005). A part whose pinned topology declares no second
 * core or independently supplied coprocessor image stays explicitly
 * {@code UNAVAILABLE} with a reason; no family or wildcard inference ever
 * creates one. Every exact part retains its {@code PLANNED} support state and
 * no Ghidra mutation is performed here.</p>
 */
package io.github.rezabakhshi.embedra.targets.stm32.workspace;
