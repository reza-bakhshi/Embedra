package io.github.rezabakhshi.embedra.pack;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** One ESP peripheral window and its register aliases. */
public final class EspPeripheral {
    private final String name;

    private final List<String> aliases;

    private final long baseAddress;

    private final long endExclusive;

    private final List<EspPeripheralRegister> registers;

    private final Map<String, EspPeripheralRegister> registersByName;

    public EspPeripheral(String name, List<String> aliases, long baseAddress,
            long endExclusive, List<EspPeripheralRegister> registers) {
        PackManifest.requireIdentifier(name, "peripheral name");
        this.name = name;
        this.aliases = List.copyOf(aliases);
        this.aliases.forEach(alias -> PackManifest.requireIdentifier(alias,
            "peripheral alias"));
        if (baseAddress < 0 || endExclusive <= baseAddress
            || endExclusive > 0x1_0000_0000L) {
            throw new IllegalArgumentException("Peripheral range is invalid");
        }
        this.baseAddress = baseAddress;
        this.endExclusive = endExclusive;
        this.registers = List.copyOf(registers);
        Map<String, EspPeripheralRegister> indexed = new HashMap<>();
        for (EspPeripheralRegister register : this.registers) {
            if (register.address() < baseAddress || register.address() + 4 > endExclusive) {
                throw new IllegalArgumentException("Register is outside peripheral range");
            }
            for (String registerName : register.names()) {
                if (indexed.put(registerName, register) != null) {
                    throw new IllegalArgumentException("Duplicate register name");
                }
            }
        }
        registersByName = Map.copyOf(indexed);
    }

    public String name() {
        return name;
    }

    public List<String> aliases() {
        return aliases;
    }

    public long baseAddress() {
        return baseAddress;
    }

    public long endExclusive() {
        return endExclusive;
    }

    public List<EspPeripheralRegister> registers() {
        return registers;
    }

    public EspPeripheralRegister requireRegister(String registerName) {
        EspPeripheralRegister register = registersByName.get(registerName);
        if (register == null) {
            throw new IllegalArgumentException("Unknown register: " + registerName);
        }
        return register;
    }
}
