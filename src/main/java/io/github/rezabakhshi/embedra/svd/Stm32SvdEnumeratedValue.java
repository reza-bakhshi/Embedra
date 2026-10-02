package io.github.rezabakhshi.embedra.svd;

import java.util.Objects;

/** One named numeric value from an STM32 CMSIS-SVD field. */
public record Stm32SvdEnumeratedValue(
        String name,
        long value,
        String description,
        boolean isDefault) {
    public Stm32SvdEnumeratedValue {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(description, "description");
        if (name.isBlank()) {
            throw new IllegalArgumentException("SVD enumerated value name must not be blank");
        }
    }
}
