package io.github.rezabakhshi.embedra.targets.stm8.peripheral;

import java.util.Objects;

/**
 * Immutable definition of an 8-bit register bitfield for STM8 peripherals.
 */
public record Stm8BitField(
        String name,
        int bitOffset,
        int bitWidth,
        int mask,
        String access,
        String description) {

    public Stm8BitField {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(access, "access must not be null");
        description = description == null ? "" : description;

        if (name.isBlank()) {
            throw new IllegalArgumentException("Bitfield name must not be blank");
        }
        if (bitOffset < 0 || bitOffset > 7) {
            throw new IllegalArgumentException("bitOffset out of range (0-7): " + bitOffset);
        }
        if (bitWidth < 1 || bitWidth > 8) {
            throw new IllegalArgumentException("bitWidth out of range (1-8): " + bitWidth);
        }
        if (bitOffset + bitWidth > 8) {
            throw new IllegalArgumentException("Bitfield exceeds 8-bit boundary: " + (bitOffset + bitWidth));
        }
        int expectedMask = ((1 << bitWidth) - 1) << bitOffset;
        if (mask != expectedMask) {
            throw new IllegalArgumentException(String.format(
                "Mask mismatch: specified 0x%02X, expected 0x%02X for offset %d width %d",
                mask, expectedMask, bitOffset, bitWidth));
        }
    }

    public static Stm8BitField singleBit(String name, int bitOffset, String access, String description) {
        return new Stm8BitField(name, bitOffset, 1, 1 << bitOffset, access, description);
    }
}
