/**
 * Ghidra-independent STM32 library signature-pack matching, firmware diff, and
 * CTF enrichment.
 *
 * <p>Signatures are compiler/optimization/family-indexed masked byte patterns
 * derived only from a pinned redistributable source. A match is evidence-backed
 * and never promotes an exact-part support state; missing evidence produces an
 * explicit non-match rather than a guess. The firmware diff applies the shared
 * T025 change-kind contract over confirmed per-part artifacts, and the CTF
 * enrichment reuses the shared matcher plus the pinned T044 TrustZone records
 * to rank provenance-bearing leads; unavailable evidence stays explicitly
 * unavailable (STM-012, STM-019).
 */
package io.github.rezabakhshi.embedra.analyzers.stm32;
