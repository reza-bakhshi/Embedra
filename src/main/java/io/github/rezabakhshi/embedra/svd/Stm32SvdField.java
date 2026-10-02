package io.github.rezabakhshi.embedra.svd;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

/** One validated bit field in an STM32 memory-mapped SVD register. */
public record Stm32SvdField(
        String name,
        String description,
        int bitOffset,
        int bitWidth,
        EspSvdAccess access,
        OptionalLong resetValue,
        Optional<String> readAction,
        List<Stm32SvdEnumeratedValue> enumeratedValues) {
    public Stm32SvdField {
        requireText(name, "field name");
        Objects.requireNonNull(description, "description");
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(resetValue, "resetValue");
        readAction = Objects.requireNonNull(readAction, "readAction");
        enumeratedValues = List.copyOf(enumeratedValues);
        if (bitOffset < 0 || bitWidth <= 0 || bitOffset + bitWidth > 64) {
            throw new IllegalArgumentException("SVD field bit range is invalid");
        }
        Set<String> enumNames = new HashSet<>();
        for (Stm32SvdEnumeratedValue value : enumeratedValues) {
            if (!fitsFieldWidth(value.value(), bitWidth)) {
                throw new IllegalArgumentException(
                    "SVD enumerated value does not fit its field width");
            }
            if (!enumNames.add(value.name())) {
                throw new IllegalArgumentException("Duplicate SVD enumerated value name");
            }
        }
    }

    public boolean hasEnumeration() {
        return !enumeratedValues.isEmpty();
    }

    private static boolean fitsFieldWidth(long value, int bitWidth) {
        if (bitWidth >= 64) {
            return true;
        }
        long unsignedMask = (1L << bitWidth) - 1;
        if ((value & ~unsignedMask) == 0) {
            return true;
        }
        long minimumSigned = -(1L << (bitWidth - 1));
        long maximumSigned = (1L << (bitWidth - 1)) - 1;
        return value >= minimumSigned && value <= maximumSigned;
    }

    private static void requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
