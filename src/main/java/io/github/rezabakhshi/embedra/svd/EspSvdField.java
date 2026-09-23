package io.github.rezabakhshi.embedra.svd;

import java.util.Objects;
import java.util.List;

/** One validated bit field in a memory-mapped SVD register. */
public record EspSvdField(
        String name,
        String description,
        int bitOffset,
        int bitWidth,
        EspSvdAccess access,
        List<EspSvdEnumeratedValue> enumeratedValues) {
    public EspSvdField {
        requireText(name, "field name");
        description = Objects.requireNonNull(description, "description");
        Objects.requireNonNull(access, "access");
        enumeratedValues = List.copyOf(enumeratedValues);
        if (bitOffset < 0 || bitWidth <= 0 || bitOffset + bitWidth > 64) {
            throw new IllegalArgumentException("SVD field bit range is invalid");
        }
    }

    private static void requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
