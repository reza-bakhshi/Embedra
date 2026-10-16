package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.Objects;

/**
 * Immutable definition of a register bitfield for Atmel/Microchip peripherals (AVR and SAM).
 */
public record AtmelBitField(
        String name,
        int bitOffset,
        int bitWidth,
        long mask,
        String access,
        String description) {

    public AtmelBitField {
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
        if (mask <= 0L) {
            throw new IllegalArgumentException("Bitfield mask must be positive: " + mask);
        }
    }

    public static AtmelBitField singleBit(String name, int bitOffset, String access, String description) {
        return new AtmelBitField(name, bitOffset, 1, 1L << bitOffset, access, description);
    }
}
