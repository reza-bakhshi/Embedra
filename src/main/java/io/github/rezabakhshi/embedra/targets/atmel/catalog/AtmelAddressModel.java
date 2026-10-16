package io.github.rezabakhshi.embedra.targets.atmel.catalog;

/**
 * Address space architecture model for Atmel / Microchip microcontrollers.
 */
public enum AtmelAddressModel {
    /** Classic 8-bit AVR Harvard architecture with separate code, data, eeprom, and io address spaces. */
    HARVARD_SEPARATE,

    /** Modern AVRxt 8-bit architecture with Harvard execution and unified linear data space aliasing. */
    HARVARD_UNIFIED_DATA_ALIAS,

    /** 32-bit ARM Cortex-M unified linear physical memory architecture. */
    LINEAR_32BIT
}
