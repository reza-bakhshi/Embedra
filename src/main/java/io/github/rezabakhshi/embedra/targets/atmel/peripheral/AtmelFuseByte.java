package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable definition of an Atmel non-volatile fuse byte or register.
 */
public record AtmelFuseByte(
        String name,
        long address,
        int sizeBits,
        long defaultValue,
        String description,
        List<AtmelFuseBit> bits) {

    public AtmelFuseByte {
        Objects.requireNonNull(name, "name must not be null");
        description = description == null ? "" : description;
        bits = bits == null ? List.of() : List.copyOf(bits);

        if (name.isBlank()) {
            throw new IllegalArgumentException("Fuse byte name must not be blank");
        }
        if (address < 0L) {
            throw new IllegalArgumentException("Fuse byte address must not be negative: " + address);
        }
        if (sizeBits <= 0 || sizeBits > 64) {
            throw new IllegalArgumentException("Fuse byte sizeBits out of range (1-64): " + sizeBits);
        }
    }

    public Optional<AtmelFuseBit> findBitByName(String bitName) {
        if (bitName == null || bitName.isBlank()) {
            return Optional.empty();
        }
        for (AtmelFuseBit b : bits) {
            if (b.name().equalsIgnoreCase(bitName.trim())) {
                return Optional.of(b);
            }
        }
        return Optional.empty();
    }
}
