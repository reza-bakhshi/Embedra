package io.github.rezabakhshi.embedra.svd;

import java.util.Objects;

/** One CMSIS-SVD peripheral interrupt line with its exact encoded number. */
public record Stm32SvdInterrupt(String name, int number, String description) {
    public Stm32SvdInterrupt {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(description, "description");
        if (name.isBlank()) {
            throw new IllegalArgumentException("SVD interrupt name must not be blank");
        }
        if (number < -16 || number > 65535) {
            throw new IllegalArgumentException("SVD interrupt number is out of range");
        }
    }
}
