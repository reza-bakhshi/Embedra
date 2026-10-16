package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable definition of an Atmel/Microchip hardware register.
 */
public record AtmelRegister(
        String name,
        long address,
        long offset,
        int widthBits,
        String access,
        String description,
        List<AtmelBitField> bitfields) {

    public AtmelRegister {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(access, "access must not be null");
        description = description == null ? "" : description;
        bitfields = bitfields == null ? List.of() : List.copyOf(bitfields);

        if (name.isBlank()) {
            throw new IllegalArgumentException("Register name must not be blank");
        }
        if (address < 0L) {
            throw new IllegalArgumentException("Register address must not be negative: " + address);
        }
        if (widthBits != 8 && widthBits != 16 && widthBits != 24 && widthBits != 32 && widthBits != 64) {
            throw new IllegalArgumentException("Unsupported register width: " + widthBits);
        }
    }

    public long effectiveAddress(long peripheralBaseAddress) {
        return (address >= peripheralBaseAddress) ? address : (peripheralBaseAddress + address);
    }

    public Optional<AtmelBitField> findBitFieldByName(String bitfieldName) {
        if (bitfieldName == null || bitfieldName.isBlank()) {
            return Optional.empty();
        }
        for (AtmelBitField bf : bitfields) {
            if (bf.name().equalsIgnoreCase(bitfieldName.trim())) {
                return Optional.of(bf);
            }
        }
        return Optional.empty();
    }
}
