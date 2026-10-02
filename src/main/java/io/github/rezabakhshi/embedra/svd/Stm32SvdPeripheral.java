package io.github.rezabakhshi.embedra.svd;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** One SVD peripheral window and its expanded registers and interrupt lines. */
public final class Stm32SvdPeripheral {
    private final String name;

    private final String description;

    private final String groupName;

    private final long baseAddress;

    private final long endExclusive;

    private final List<Stm32SvdRegister> registers;

    private final List<Stm32SvdInterrupt> interrupts;

    private final Map<String, Stm32SvdRegister> registersByName;

    public Stm32SvdPeripheral(String name, String description, String groupName,
            long baseAddress, long endExclusive, List<Stm32SvdRegister> registers,
            List<Stm32SvdInterrupt> interrupts) {
        this.name = requireText(name, "peripheral name");
        this.description = Objects.requireNonNull(description, "description");
        this.groupName = Objects.requireNonNull(groupName, "groupName");
        if (baseAddress < 0 || endExclusive <= baseAddress || endExclusive > 0x1_0000_0000L) {
            throw new IllegalArgumentException("SVD peripheral range is invalid");
        }
        this.baseAddress = baseAddress;
        this.endExclusive = endExclusive;
        this.registers = List.copyOf(registers);
        this.interrupts = List.copyOf(interrupts);
        Map<String, Stm32SvdRegister> indexed = new HashMap<>();
        for (Stm32SvdRegister register : this.registers) {
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

    public String groupName() {
        return groupName;
    }

    public long baseAddress() {
        return baseAddress;
    }

    public long endExclusive() {
        return endExclusive;
    }

    public List<Stm32SvdRegister> registers() {
        return registers;
    }

    public List<Stm32SvdInterrupt> interrupts() {
        return interrupts;
    }

    public Stm32SvdRegister requireRegister(String registerName) {
        Stm32SvdRegister register = registersByName.get(registerName);
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
