package io.github.rezabakhshi.embedra.svd;

import java.util.Objects;

/** One named numeric value from a CMSIS-SVD field. */
public record EspSvdEnumeratedValue(String name, long value, String description) {
    public EspSvdEnumeratedValue {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(description, "description");
        if (name.isBlank()) {
            throw new IllegalArgumentException("SVD enumerated value name must not be blank");
        }
    }
}
