package io.github.rezabakhshi.embedra.targets.rp.board;

import java.util.Objects;

/**
 * Models a validated physical board pin allocation (e.g. user LED, wireless bus control).
 */
public record RpPinAllocation(
        int pin,
        String name,
        String role,
        String description) {

    public RpPinAllocation {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(role, "role must not be null");
        Objects.requireNonNull(description, "description must not be null");
        if (pin < 0 || pin > 64) {
            throw new IllegalArgumentException("Pin index out of valid range: " + pin);
        }
    }
}
