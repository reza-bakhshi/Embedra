package io.github.rezabakhshi.embedra.svd;

import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/** One expanded CMSIS-SVD register with absolute address and bit fields. */
public record EspSvdRegister(
        String name,
        String description,
        long address,
        int sizeBits,
        EspSvdAccess access,
        OptionalLong resetValue,
        List<EspSvdField> fields) {
    public EspSvdRegister {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("Register name must not be blank");
        }
        description = Objects.requireNonNull(description, "description");
        if (address < 0 || address > 0xffff_ffffL) {
            throw new IllegalArgumentException("Register address is not unsigned 32-bit");
        }
        if (sizeBits <= 0 || sizeBits > 64) {
            throw new IllegalArgumentException("Register size is invalid");
        }
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(resetValue, "resetValue");
        fields = List.copyOf(fields);
    }
}
