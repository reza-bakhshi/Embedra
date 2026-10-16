package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import java.util.Objects;

/**
 * Immutable definition of a 32-bit register bitfield for Nordic nRF peripherals.
 */
public record NordicBitField(
        String name,
        int bitOffset,
        int bitWidth,
        long mask,
        String access,
        String description) {

    public NordicBitField {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(access, "access must not be null");
        description = description == null ? "" : description;

        if (name.isBlank()) {
            throw new IllegalArgumentException("Bitfield name must not be blank");
        }
        if (bitOffset < 0 || bitOffset > 31) {
            throw new IllegalArgumentException("bitOffset out of range (0-31): " + bitOffset);
        }
        if (bitWidth < 1 || bitWidth > 32) {
            throw new IllegalArgumentException("bitWidth out of range (1-32): " + bitWidth);
        }
        if (bitOffset + bitWidth > 32) {
            throw new IllegalArgumentException("Bitfield exceeds 32-bit boundary: " + (bitOffset + bitWidth));
        }
        long expectedMask = bitWidth == 32 ? 0xFFFFFFFFL : (((1L << bitWidth) - 1L) << bitOffset);
        if (mask != expectedMask) {
            throw new IllegalArgumentException(String.format(
                "Mask mismatch: specified 0x%08X, expected 0x%08X for offset %d width %d",
                mask, expectedMask, bitOffset, bitWidth));
        }
    }

    public static NordicBitField singleBit(String name, int bitOffset, String access, String description) {
        return new NordicBitField(name, bitOffset, 1, 1L << bitOffset, access, description);
    }
}
