package io.github.rezabakhshi.embedra.targets.stm8.peripheral;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable definition of an STM8 hardware peripheral block.
 */
public record Stm8Peripheral(
        String name,
        long baseAddress,
        long endExclusive,
        String description,
        List<Stm8Register> registers) {

    public Stm8Peripheral {
        Objects.requireNonNull(name, "name must not be null");
        description = description == null ? "" : description;
        registers = registers == null ? List.of() : List.copyOf(registers);

        if (name.isBlank()) {
            throw new IllegalArgumentException("Peripheral name must not be blank");
        }
        if (baseAddress < 0x005000L || endExclusive > 0x005800L || endExclusive <= baseAddress) {
            throw new IllegalArgumentException(String.format(
                "Invalid peripheral address range: 0x%06X - 0x%06X", baseAddress, endExclusive));
        }

        Map<Long, Stm8Register> byAddress = new HashMap<>();
        Map<String, Stm8Register> byName = new HashMap<>();
        for (Stm8Register reg : registers) {
            if (reg.address() < baseAddress || reg.address() >= endExclusive) {
                throw new IllegalArgumentException(String.format(
                    "Register %s (0x%06X) is outside peripheral %s bounds [0x%06X, 0x%06X)",
                    reg.name(), reg.address(), name, baseAddress, endExclusive));
            }
            if (byAddress.put(reg.address(), reg) != null) {
                throw new IllegalArgumentException(String.format(
                    "Duplicate register address in peripheral %s: 0x%06X", name, reg.address()));
            }
            if (byName.put(reg.name(), reg) != null) {
                throw new IllegalArgumentException(String.format(
                    "Duplicate register name in peripheral %s: %s", name, reg.name()));
            }
        }
    }

    public Optional<Stm8Register> findRegisterByName(String registerName) {
        if (registerName == null || registerName.isBlank()) {
            return Optional.empty();
        }
        for (Stm8Register reg : registers) {
            if (reg.name().equalsIgnoreCase(registerName.trim())) {
                return Optional.of(reg);
            }
        }
        return Optional.empty();
    }

    public Optional<Stm8Register> findRegisterAt(long address) {
        for (Stm8Register reg : registers) {
            if (reg.address() == address) {
                return Optional.of(reg);
            }
        }
        return Optional.empty();
    }

    public boolean containsAddress(long address) {
        return address >= baseAddress && address < endExclusive;
    }
}
