package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import java.util.Objects;

/**
 * Validates EasyDMA register semantics, memory aperture boundaries, and buffer alignment.
 */
public final class NordicEasyDmaValidator {

    public static final long SRAM_BASE = 0x20000000L;

    public static final long SRAM_LIMIT = 0x30000000L;

    public static final long FLASH_BASE = 0x00000000L;

    public static final long FLASH_LIMIT = 0x10000000L;

    public static final long QSPI_XIP_BASE = 0x12000000L;

    public static final long QSPI_XIP_LIMIT = 0x16000000L;

    public static final long PERIPHERALS_BASE = 0x40000000L;

    public static final long PERIPHERALS_LIMIT = 0x60000000L;

    public static final long CONFIG_BASE = 0x10000000L;

    public static final long CONFIG_LIMIT = 0x10002000L;

    public static final int MAX_BUFFER_BYTES = 65535;

    private NordicEasyDmaValidator() {
    }

    /**
     * Validates that an EasyDMA pointer target address has strict 32-bit word alignment
     * and resides in a legal memory aperture (internal SRAM, Flash, or QSPI XIP),
     * strictly rejecting MMIO peripherals and configuration blocks.
     */
    public static boolean isValidPointerTarget(long targetAddress, boolean readOnly) {
        // Enforce 32-bit (4-byte) alignment
        if ((targetAddress & 0x03L) != 0L) {
            return false;
        }

        // Strictly reject MMIO apertures and FICR/UICR
        if (targetAddress >= PERIPHERALS_BASE && targetAddress < PERIPHERALS_LIMIT) {
            return false;
        }
        if (targetAddress >= CONFIG_BASE && targetAddress < CONFIG_LIMIT) {
            return false;
        }

        // Check valid memory apertures
        boolean inSram = targetAddress >= SRAM_BASE && targetAddress < SRAM_LIMIT;
        if (inSram) {
            return true;
        }

        if (readOnly) {
            // Flash and QSPI XIP are permissible for read-only DMA (TX)
            boolean inFlash = targetAddress >= FLASH_BASE && targetAddress < FLASH_LIMIT;
            boolean inQspi = targetAddress >= QSPI_XIP_BASE && targetAddress < QSPI_XIP_LIMIT;
            return inFlash || inQspi;
        }

        return false;
    }

    /**
     * Enforces pointer target validation, throwing IllegalArgumentException on violation.
     */
    public static void validatePointerTarget(long targetAddress, boolean readOnly) {
        if ((targetAddress & 0x03L) != 0L) {
            throw new IllegalArgumentException(String.format(
                "EasyDMA pointer 0x%08X is not 32-bit aligned (bits 1:0 must be zero)", targetAddress));
        }
        if (targetAddress >= PERIPHERALS_BASE && targetAddress < PERIPHERALS_LIMIT) {
            throw new IllegalArgumentException(String.format(
                "EasyDMA pointer 0x%08X targets MMIO peripheral aperture (0x40000000-0x5FFFFFFF)", targetAddress));
        }
        if (targetAddress >= CONFIG_BASE && targetAddress < CONFIG_LIMIT) {
            throw new IllegalArgumentException(String.format(
                "EasyDMA pointer 0x%08X targets non-volatile configuration memory (FICR/UICR)", targetAddress));
        }
        if (!isValidPointerTarget(targetAddress, readOnly)) {
            throw new IllegalArgumentException(String.format(
                "EasyDMA pointer 0x%08X is outside valid memory apertures (SRAM, or Flash/QSPI for read)",
                targetAddress));
        }
    }

    /**
     * Validates an EasyDMA buffer count (MAXCNT or AMOUNT).
     */
    public static void validateBufferCount(int count, int maxAllowed) {
        if (count < 0) {
            throw new IllegalArgumentException("EasyDMA buffer count must be non-negative: " + count);
        }
        if (count > maxAllowed || count > MAX_BUFFER_BYTES) {
            throw new IllegalArgumentException(String.format(
                "EasyDMA buffer count %d exceeds maximum allowable limit %d", count, maxAllowed));
        }
    }

    /**
     * Validates an EasyDMA LIST configuration mode.
     * Modes: 0 = Disabled, 1 = ArrayList.
     */
    public static void validateListMode(int listMode) {
        if (listMode < 0 || listMode > 1) {
            throw new IllegalArgumentException("Invalid EasyDMA LIST mode: " + listMode + " (expected 0 or 1)");
        }
    }
}
