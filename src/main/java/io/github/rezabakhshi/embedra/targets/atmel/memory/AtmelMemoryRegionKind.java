package io.github.rezabakhshi.embedra.targets.atmel.memory;

/**
 * Functional classification of an Atmel / Microchip memory region.
 */
public enum AtmelMemoryRegionKind {
    /** Non-volatile executable program flash memory. */
    CODE_FLASH,

    /** Internal SRAM volatile data memory. */
    INTERNAL_SRAM,

    /** Non-volatile data EEPROM memory. */
    DATA_EEPROM,

    /** Dedicated I/O register memory. */
    IO_REGISTERS,

    /** Flash program memory read-only window aliased into data space (AVR-Dx). */
    FLASH_DATA_ALIAS,

    /** Memory-mapped peripheral registers. */
    PERIPHERALS_MMIO,

    /** Factory or user non-volatile configuration fuse bytes. */
    FUSES,

    /** Read-only boot ROM (e.g. SAM-BA). */
    BOOT_ROM
}
