package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

/**
 * Fuse bit polarity indicator for Atmel microcontrollers.
 */
public enum AtmelFusePolarity {
    PROGRAMMED_LOW,
    PROGRAMMED_HIGH;

    public boolean isProgrammed(int bitVal) {
        if (this == PROGRAMMED_LOW) {
            return bitVal == 0;
        }
        return bitVal != 0;
    }
}
