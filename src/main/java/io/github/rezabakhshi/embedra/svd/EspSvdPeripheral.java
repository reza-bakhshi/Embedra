package io.github.rezabakhshi.embedra.svd;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** One SVD peripheral window and its expanded registers. */
public final class EspSvdPeripheral {
    private final String name;

    private final String description;

    private final long baseAddress;

    private final long endExclusive;

    private final List<EspSvdRegister> registers;

    private final Map<String, EspSvdRegister> registersByName;

    public EspSvdPeripheral(String name, String description, long baseAddress,
            long endExclusive, List<EspSvdRegister> registers) {
        this.name = requireText(name, "peripheral name");
        this.description = Objects.requireNonNull(description, "description");
        if (baseAddress < 0 || endExclusive <= baseAddress
            || endExclusive > 0x1_0000_0000L) {
            throw new IllegalArgumentException("SVD peripheral range is invalid");
        }
        this.baseAddress = baseAddress;
        this.endExclusive = endExclusive;
        this.registers = List.copyOf(registers);
        Map<String, EspSvdRegister> indexed = new HashMap<>();
        for (EspSvdRegister register : this.registers) {
            if (register.address() < baseAddress || register.address() >= endExclusive) {
                throw new IllegalArgumentException("SVD register is outside its peripheral");
            }
            if (indexed.put(register.name(), register) != null) {
                throw new IllegalArgumentException("Duplicate SVD register name");
            }
        }
        registersByName = Map.copyOf(indexed);
    }

    public String name() {
        return name;
    }

    public String description() {
        return description;
    }

    public long baseAddress() {
        return baseAddress;
    }

    public long endExclusive() {
        return endExclusive;
    }

    public List<EspSvdRegister> registers() {
        return registers;
    }

    public EspSvdRegister requireRegister(String registerName) {
        EspSvdRegister register = registersByName.get(registerName);
        if (register == null) {
            throw new IllegalArgumentException("Unknown SVD register: " + registerName);
        }
        return register;
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
