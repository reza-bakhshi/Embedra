package io.github.rezabakhshi.embedra.svd;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

/** One expanded STM32 CMSIS-SVD register with absolute address and bit fields. */
public record Stm32SvdRegister(
        String name,
        String description,
        long address,
        int sizeBits,
        EspSvdAccess access,
        OptionalLong resetValue,
        OptionalLong resetMask,
        List<Stm32SvdField> fields,
        Optional<String> alternateRegister,
        Optional<String> alternateGroup) {
    public Stm32SvdRegister {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("SVD register name must not be blank");
        }
        description = Objects.requireNonNull(description, "description");
        if (address < 0 || address > 0xffff_ffffL) {
            throw new IllegalArgumentException("SVD register address is not unsigned 32-bit");
        }
        if (sizeBits <= 0 || sizeBits > 64) {
            throw new IllegalArgumentException("SVD register size is invalid");
        }
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(resetValue, "resetValue");
        Objects.requireNonNull(resetMask, "resetMask");
        fields = List.copyOf(fields);
        alternateRegister = Objects.requireNonNull(alternateRegister, "alternateRegister");
        alternateGroup = Objects.requireNonNull(alternateGroup, "alternateGroup");
        Set<String> fieldNames = new HashSet<>();
        List<Stm32SvdField> placed = new ArrayList<>(fields.size());
        for (Stm32SvdField field : fields) {
            if (field.bitOffset() + field.bitWidth() > sizeBits) {
                throw new IllegalArgumentException(
                    "SVD field exceeds its register size");
            }
            if (!fieldNames.add(field.name())) {
                throw new IllegalArgumentException("Duplicate SVD field name");
            }
            for (Stm32SvdField other : placed) {
                if (field.bitOffset() < other.bitOffset() + other.bitWidth()
                        && other.bitOffset() < field.bitOffset() + field.bitWidth()) {
                    throw new IllegalArgumentException("Overlapping SVD fields");
                }
            }
            placed.add(field);
        }
    }

    /** True when this register documents another view at the same or a related address. */
    public boolean isAlternateView() {
        return alternateRegister.isPresent() || alternateGroup.isPresent();
    }

    public boolean hasFields() {
        return !fields.isEmpty();
    }
}
