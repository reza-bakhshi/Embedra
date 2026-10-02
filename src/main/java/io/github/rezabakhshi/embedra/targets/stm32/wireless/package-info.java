/**
 * Pure STM32 wireless/network-core distinctions for exact curated parts.
 *
 * <p>A wireless record classifies one exact WB/WB0/WBA/WL3 part from pinned,
 * digest-checked inputs only: the T032 curated catalog family, the T039
 * memory plan topology, the T040 per-core SVD applicability, the T044
 * security record, and the T045 workspace plan. A part with a pinned
 * separately-programmable network core (the WB55/WB15 CPU2 radio processor)
 * is planned {@code NETWORK_CORE_PINNED} with an independently supplied
 * coprocessor-firmware contract whose binding stays configuration-dependent;
 * the remaining wireless parts are planned
 * {@code SINGLE_APPLICATION_CORE} with no invented network core, coprocessor
 * image, radio register window, or radio-to-CPU memory attribution
 * (STM-008, STM-014, STM-019, STM-020, TOPO-001..TOPO-005). Every part keeps
 * its {@code PLANNED} support state and no Ghidra mutation is performed here.
 */
package io.github.rezabakhshi.embedra.targets.stm32.wireless;
