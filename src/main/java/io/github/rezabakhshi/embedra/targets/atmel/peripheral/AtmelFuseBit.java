package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.Objects;

/**
 * Immutable definition of an Atmel non-volatile configuration fuse bit / field.
 */
public record AtmelFuseBit(
        String name,
        int bitOffset,
        int bitWidth,
        long mask,
        AtmelFusePolarity polarity,
        String description) {

    public AtmelFuseBit {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(polarity, "polarity must not be null");
        description = description == null ? "" : description;

        if (name.isBlank()) {
            throw new IllegalArgumentException("Fuse bit name must not be blank");
        }
        if (bitOffset < 0 || bitOffset > 31) {
            throw new IllegalArgumentException("bitOffset out of range (0-31): " + bitOffset);
        }
        if (bitWidth < 1 || bitWidth > 32) {
            throw new IllegalArgumentException("bitWidth out of range (1-32): " + bitWidth);
        }
        if (bitOffset + bitWidth > 32) {
            throw new IllegalArgumentException("Fuse bit exceeds 32-bit boundary: " + (bitOffset + bitWidth));
        }
        if (mask <= 0L) {
            throw new IllegalArgumentException("Fuse bit mask must be positive: " + mask);
        }
    }

    public boolean isProgrammed(long byteValue) {
        long extracted = (byteValue >> bitOffset) & ((1L << bitWidth) - 1L);
        return polarity.isProgrammed((int) extracted);
    }
}
