package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.Objects;

/**
 * Immutable definition of an Atmel/Microchip parallel I/O port mapping.
 */
public record AtmelIoPort(
        String name,
        int pinCount,
        String dataRegister,
        String directionRegister,
        String inputRegister) {

    public AtmelIoPort {
        Objects.requireNonNull(name, "name must not be null");
        dataRegister = dataRegister == null ? "" : dataRegister;
        directionRegister = directionRegister == null ? "" : directionRegister;
        inputRegister = inputRegister == null ? "" : inputRegister;

        if (name.isBlank()) {
            throw new IllegalArgumentException("I/O Port name must not be blank");
        }
        if (pinCount <= 0 || pinCount > 64) {
            throw new IllegalArgumentException("I/O Port pinCount out of range (1-64): " + pinCount);
        }
    }
}
