package io.github.rezabakhshi.embedra.targets.rp;

/**
 * Memory region categories for Raspberry Pi silicon and board architectures.
 */
public enum RpMemoryRegionKind {
    BOOT_ROM,
    FLASH_XIP,
    INTERNAL_FLASH,
    SRAM,
    PERIPHERALS,
    ATOMIC_ALIASES,
    SIO,
    OTP,
    PPB,
    XIP_MAINTENANCE,
    PSRAM
}
