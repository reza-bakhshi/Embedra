package io.github.rezabakhshi.embedra.targets.stm8.peripheral;

import java.util.List;
import java.util.Objects;

/**
 * Immutable definition of an 8-bit byte-wide memory-mapped register on STM8 (STM8-008).
 */
public record Stm8Register(
        String name,
        long address,
        long offset,
        int widthBits,
        String description,
        List<Stm8BitField> bitfields) {

    public Stm8Register {
        Objects.requireNonNull(name, "name must not be null");
        description = description == null ? "" : description;
        bitfields = bitfields == null ? List.of() : List.copyOf(bitfields);

        if (name.isBlank()) {
            throw new IllegalArgumentException("Register name must not be blank");
        }
        if (address < 0x005000L || address > 0x0057FFL) {
            throw new IllegalArgumentException("Register address outside STM8 peripheral range: 0x"
                + Long.toHexString(address));
        }
        if (offset < 0) {
            throw new IllegalArgumentException("Offset must be non-negative: " + offset);
        }
        if (widthBits != 8) {
            throw new IllegalArgumentException("STM8 registers must have 8-bit width, got: " + widthBits);
        }

        // Validate non-overlapping bitfields
        for (int i = 0; i < bitfields.size(); i++) {
            Stm8BitField b1 = bitfields.get(i);
            for (int j = i + 1; j < bitfields.size(); j++) {
                Stm8BitField b2 = bitfields.get(j);
                if ((b1.mask() & b2.mask()) != 0) {
                    throw new IllegalArgumentException(String.format(
                        "Bitfield collision in register %s: %s (0x%02X) overlaps %s (0x%02X)",
                        name, b1.name(), b1.mask(), b2.name(), b2.mask()));
                }
            }
        }
    }
}
