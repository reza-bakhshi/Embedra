package io.github.rezabakhshi.embedra.targets.stm8.memory;

/**
 * Functional category of an STM8 memory region.
 */
public enum Stm8MemoryRegionKind {
    RAM,
    EEPROM,
    OPTION_BYTES,
    PERIPHERALS,
    BOOT_ROM,
    FLASH
}
