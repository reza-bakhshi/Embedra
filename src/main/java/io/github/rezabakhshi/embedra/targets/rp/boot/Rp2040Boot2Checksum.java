package io.github.rezabakhshi.embedra.targets.rp.boot;

import java.util.Objects;

/**
 * Standard CRC-32 checksum calculation and verification for RP2040 boot2 second stage.
 * <p>
 * Per RP2040 Datasheet Section 2.8.1.3.1:
 * <ul>
 *   <li>Polynomial: 0x04C11DB7 (IEEE 802.3 standard)</li>
 *   <li>Initial value: 0xFFFFFFFF</li>
 *   <li>Final XOR: 0x00000000</li>
 *   <li>Bit reflection: None</li>
 * </ul>
 */
public final class Rp2040Boot2Checksum {

    public static final long POLYNOMIAL = 0x04C11DB7L;

    public static final long INITIAL_VALUE = 0xFFFFFFFFL;

    public static final int BOOT2_SIZE = 256;

    public static final int CHECKSUMMED_SIZE = 252;

    public static final long PLACEHOLDER_CRC2 = 0x43524332L;

    private Rp2040Boot2Checksum() {
    }

    /**
     * Calculates the RP2040 boot2 CRC-32 over the given byte range.
     */
    public static long calculate(byte[] data, int offset, int length) {
        Objects.requireNonNull(data, "data must not be null");
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IndexOutOfBoundsException("Invalid offset/length for buffer size " + data.length);
        }

        long crc = INITIAL_VALUE;
        for (int i = 0; i < length; i++) {
            crc ^= ((long) (data[offset + i] & 0xFF) << 24);
            for (int bit = 0; bit < 8; bit++) {
                if ((crc & 0x80000000L) != 0) {
                    crc = ((crc << 1) ^ POLYNOMIAL) & 0xFFFFFFFFL;
                } else {
                    crc = (crc << 1) & 0xFFFFFFFFL;
                }
            }
        }
        return crc & 0xFFFFFFFFL;
    }

    /**
     * Validates a 256-byte boot2 block against its trailing 4-byte checksum.
     */
    public static boolean validate(byte[] boot2) {
        if (boot2 == null || boot2.length < BOOT2_SIZE) {
            return false;
        }
        long calculated = calculate(boot2, 0, CHECKSUMMED_SIZE);
        long stored = readU32Le(boot2, CHECKSUMMED_SIZE);
        return calculated == stored;
    }

    public static long readStoredChecksum(byte[] boot2) {
        if (boot2 == null || boot2.length < BOOT2_SIZE) {
            throw new IllegalArgumentException("Boot2 data must be at least 256 bytes");
        }
        return readU32Le(boot2, CHECKSUMMED_SIZE);
    }

    private static long readU32Le(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF))
                | ((long) (data[offset + 1] & 0xFF) << 8)
                | ((long) (data[offset + 2] & 0xFF) << 16)
                | ((long) (data[offset + 3] & 0xFF) << 24);
    }
}
