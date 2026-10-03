package io.github.rezabakhshi.embedra.targets.rp.catalog;

import java.util.Objects;

/**
 * An individual SRAM memory bank in a Raspberry Pi silicon part.
 */
public record RpSramBank(
        String name,
        long baseAddress,
        long sizeBytes,
        boolean striped) {

    public RpSramBank {
        Objects.requireNonNull(name, "name must not be null");
        if (name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        if (sizeBytes <= 0) {
            throw new IllegalArgumentException("sizeBytes must be positive: " + sizeBytes);
        }
    }
}
