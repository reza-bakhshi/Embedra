package io.github.rezabakhshi.embedra.targets.rp;

import java.util.Optional;

/**
 * Model of the RP2350 8 KiB One-Time Programmable (OTP) memory.
 * <p>
 * Holds hardware security configuration, Secure Boot public key hashes,
 * rollback counter limits, and unique device identity.
 */
public final class Rp2350OtpMemory {

    public static final long OTP_BASE = 0x40130000L;

    public static final long OTP_SIZE_BYTES = 8 * 1024L;

    public static final int WORD_COUNT = 2048;

    // Standard RP2350 OTP row allocations
    public static final int ROW_CHIP_ID = 0x000;

    public static final int ROW_BOOT_FLAGS = 0x010;

    public static final int ROW_SECURE_BOOT_KEY0 = 0x040;

    public static final int ROW_SECURE_BOOT_KEY1 = 0x048;

    public static final int ROW_SECURE_BOOT_KEY2 = 0x050;

    public static final int ROW_SECURE_BOOT_KEY3 = 0x058;

    public static final int ROW_ROLLBACK_LIMIT = 0x060;

    private Rp2350OtpMemory() {
    }

    public static boolean containsAddress(long address) {
        return address >= OTP_BASE && address < OTP_BASE + OTP_SIZE_BYTES;
    }

    public static Optional<String> rowDescription(int row) {
        if (row >= ROW_SECURE_BOOT_KEY0 && row < ROW_SECURE_BOOT_KEY0 + 8) {
            return Optional.of("Secure Boot Key Slot 0 (SHA-256 hash word " + (row - ROW_SECURE_BOOT_KEY0) + ")");
        }
        if (row >= ROW_SECURE_BOOT_KEY1 && row < ROW_SECURE_BOOT_KEY1 + 8) {
            return Optional.of("Secure Boot Key Slot 1 (SHA-256 hash word " + (row - ROW_SECURE_BOOT_KEY1) + ")");
        }
        if (row >= ROW_SECURE_BOOT_KEY2 && row < ROW_SECURE_BOOT_KEY2 + 8) {
            return Optional.of("Secure Boot Key Slot 2 (SHA-256 hash word " + (row - ROW_SECURE_BOOT_KEY2) + ")");
        }
        if (row >= ROW_SECURE_BOOT_KEY3 && row < ROW_SECURE_BOOT_KEY3 + 8) {
            return Optional.of("Secure Boot Key Slot 3 (SHA-256 hash word " + (row - ROW_SECURE_BOOT_KEY3) + ")");
        }
        return switch (row) {
            case ROW_CHIP_ID -> Optional.of("Unique Chip Hardware Identifier");
            case ROW_BOOT_FLAGS -> Optional.of("Security Boot Configuration Flags");
            case ROW_ROLLBACK_LIMIT -> Optional.of("Monotonic Firmware Rollback Limit");
            default -> Optional.empty();
        };
    }
}
