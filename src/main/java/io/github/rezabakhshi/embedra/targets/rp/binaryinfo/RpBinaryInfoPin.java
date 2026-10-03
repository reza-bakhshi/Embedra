package io.github.rezabakhshi.embedra.targets.rp.binaryinfo;

import java.util.Objects;
import java.util.Optional;

/**
 * Parsed pin mapping from a Pico SDK binary info block.
 */
public record RpBinaryInfoPin(
        long pinMask,
        String label,
        Optional<Integer> function) {

    public RpBinaryInfoPin {
        Objects.requireNonNull(label, "label must not be null");
        Objects.requireNonNull(function, "function must not be null");
    }

    /**
     * Checks if this pin mapping applies to a specific GPIO pin number.
     */
    public boolean coversPin(int pinNumber) {
        if (pinNumber < 0 || pinNumber > 63) {
            return false;
        }
        return (pinMask & (1L << pinNumber)) != 0;
    }
}
