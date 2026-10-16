package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable definition of a Nordic hardware peripheral block within MMIO aperture boundaries.
 */
public record NordicPeripheral(
        String name,
        long baseAddress,
        long endExclusive,
        String description,
        List<NordicRegister> registers) {

    public NordicPeripheral {
        Objects.requireNonNull(name, "name must not be null");
        description = description == null ? "" : description;
        registers = registers == null ? List.of() : List.copyOf(registers);

        if (name.isBlank()) {
            throw new IllegalArgumentException("Peripheral name must not be blank");
        }
        if ((baseAddress & 0x03L) != 0L || (endExclusive & 0x03L) != 0L) {
            throw new IllegalArgumentException(String.format(
                "Peripheral %s base (0x%08X) or end (0x%08X) is not 32-bit aligned",
                name, baseAddress, endExclusive));
        }
        if (endExclusive <= baseAddress) {
            throw new IllegalArgumentException(String.format(
                "Peripheral %s endExclusive (0x%08X) must be strictly greater than baseAddress (0x%08X)",
                name, endExclusive, baseAddress));
        }

        // Validate MMIO apertures: 0x40000000-0x50000000 (Non-Secure) or 0x50000000-0x60000000 (Secure)
        boolean inNonSecure = baseAddress >= 0x40000000L && endExclusive <= 0x50000000L;
        boolean inSecure = baseAddress >= 0x50000000L && endExclusive <= 0x60000000L;
        if (!inNonSecure && !inSecure) {
            throw new IllegalArgumentException(String.format(
                "Peripheral %s address range [0x%08X, 0x%08X) is outside MMIO apertures (0x40000000-0x60000000)",
                name, baseAddress, endExclusive));
        }

        Map<Long, NordicRegister> byAddress = new HashMap<>();
        Map<String, NordicRegister> byName = new HashMap<>();
        for (NordicRegister reg : registers) {
            if (reg.address() < baseAddress || reg.address() >= endExclusive) {
                throw new IllegalArgumentException(String.format(
                    "Register %s (0x%08X) is outside peripheral %s bounds [0x%08X, 0x%08X)",
                    reg.name(), reg.address(), name, baseAddress, endExclusive));
            }
            if (byAddress.put(reg.address(), reg) != null) {
                throw new IllegalArgumentException(String.format(
                    "Duplicate register address in peripheral %s: 0x%08X", name, reg.address()));
            }
            if (byName.put(reg.name(), reg) != null) {
                throw new IllegalArgumentException(String.format(
                    "Duplicate register name in peripheral %s: %s", name, reg.name()));
            }
        }
    }

    public Optional<NordicRegister> findRegisterByName(String registerName) {
        if (registerName == null || registerName.isBlank()) {
            return Optional.empty();
        }
        for (NordicRegister reg : registers) {
            if (reg.name().equalsIgnoreCase(registerName.trim())) {
                return Optional.of(reg);
            }
        }
        return Optional.empty();
    }

    public Optional<NordicRegister> findRegisterAt(long address) {
        for (NordicRegister reg : registers) {
            if (reg.address() == address) {
                return Optional.of(reg);
            }
        }
        return Optional.empty();
    }

    public boolean containsAddress(long address) {
        return address >= baseAddress && address < endExclusive;
    }

    public List<NordicRegister> easyDmaRegisters() {
        return registers.stream().filter(NordicRegister::isEasyDma).toList();
    }
}
