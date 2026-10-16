package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.Objects;

/**
 * Immutable definition of an interrupt vector line for Atmel microcontrollers.
 */
public record AtmelInterrupt(
        int index,
        String name,
        String description) {

    public AtmelInterrupt {
        Objects.requireNonNull(name, "name must not be null");
        description = description == null ? "" : description;

        if (name.isBlank()) {
            throw new IllegalArgumentException("Interrupt name must not be blank");
        }
        if (index < 0) {
            throw new IllegalArgumentException("Interrupt index must not be negative: " + index);
        }
    }
}
