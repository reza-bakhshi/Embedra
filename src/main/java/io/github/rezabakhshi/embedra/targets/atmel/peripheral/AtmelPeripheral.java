package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable definition of an Atmel/Microchip peripheral block.
 */
public record AtmelPeripheral(
        String name,
        long baseAddress,
        long endExclusive,
        String addressSpace,
        String description,
        List<AtmelRegister> registers) {

    public AtmelPeripheral {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(addressSpace, "addressSpace must not be null");
        description = description == null ? "" : description;
        registers = registers == null ? List.of() : List.copyOf(registers);

        if (name.isBlank()) {
            throw new IllegalArgumentException("Peripheral name must not be blank");
        }
        if (baseAddress < 0L) {
            throw new IllegalArgumentException("Peripheral baseAddress must not be negative: " + baseAddress);
        }
        long effEnd = (endExclusive > baseAddress) ? endExclusive : (baseAddress + endExclusive);
        if (effEnd <= baseAddress) {
            throw new IllegalArgumentException(String.format(
                "Invalid peripheral bounds for %s: base=0x%X, end=0x%X", name, baseAddress, effEnd));
        }
        for (AtmelRegister reg : registers) {
            long effAddr = reg.effectiveAddress(baseAddress);
            if (effAddr < baseAddress || effAddr >= effEnd) {
                throw new IllegalArgumentException(String.format(
                    "Register %s (0x%X) is outside peripheral %s bounds [0x%X, 0x%X)",
                    reg.name(), effAddr, name, baseAddress, effEnd));
            }
        }
    }

    public long effectiveEndAddress() {
        return (endExclusive > baseAddress) ? endExclusive : (baseAddress + endExclusive);
    }

    public List<AtmelRegister> findRegistersByName(String registerName) {
        if (registerName == null || registerName.isBlank()) {
            return List.of();
        }
        List<AtmelRegister> matches = new ArrayList<>();
        for (AtmelRegister reg : registers) {
            if (reg.name().equalsIgnoreCase(registerName.trim())) {
                matches.add(reg);
            }
        }
        return List.copyOf(matches);
    }

    public Optional<AtmelRegister> findFirstRegisterByName(String registerName) {
        if (registerName == null || registerName.isBlank()) {
            return Optional.empty();
        }
        for (AtmelRegister reg : registers) {
            if (reg.name().equalsIgnoreCase(registerName.trim())) {
                return Optional.of(reg);
            }
        }
        return Optional.empty();
    }

    public List<AtmelRegister> findRegistersByAddress(long targetAddress) {
        List<AtmelRegister> matches = new ArrayList<>();
        for (AtmelRegister reg : registers) {
            if (reg.effectiveAddress(baseAddress) == targetAddress) {
                matches.add(reg);
            }
        }
        return List.copyOf(matches);
    }

    public Optional<AtmelRegister> findFirstRegisterByAddress(long targetAddress) {
        for (AtmelRegister reg : registers) {
            if (reg.effectiveAddress(baseAddress) == targetAddress) {
                return Optional.of(reg);
            }
        }
        return Optional.empty();
    }
}
