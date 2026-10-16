package io.github.rezabakhshi.embedra.targets.nordic.memory;

/**
 * Functional classification of physical memory regions in Nordic microcontrollers.
 */
public enum NordicMemoryRegionKind {
    CODE_FLASH,
    SRAM,
    FICR,
    UICR,
    PERIPHERALS_APB,
    PERIPHERALS_SECURE,
    CRYPTOCELL,
    QSPI_XIP,
    NETWORK_FLASH,
    NETWORK_SRAM,
    NETWORK_PERIPHERALS,
    SOFTDEVICE,
    MBR,
    BOOTLOADER
}
