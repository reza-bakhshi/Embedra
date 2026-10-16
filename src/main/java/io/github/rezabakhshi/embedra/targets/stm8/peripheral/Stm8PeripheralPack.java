package io.github.rezabakhshi.embedra.targets.stm8.peripheral;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Verified immutable collection of STM8 peripheral register definitions for a family.
 */
public final class Stm8PeripheralPack {

    private final String packId;

    private final String family;

    private final String schemaId;

    private final String sourceReference;

    private final List<Stm8Peripheral> peripherals;

    private final Map<String, Stm8Peripheral> byName;

    public Stm8PeripheralPack(
            String packId,
            String family,
            String schemaId,
            String sourceReference,
            List<Stm8Peripheral> peripherals) {
        this.packId = Objects.requireNonNull(packId, "packId must not be null");
        this.family = Objects.requireNonNull(family, "family must not be null");
        this.schemaId = Objects.requireNonNull(schemaId, "schemaId must not be null");
        this.sourceReference = Objects.requireNonNull(sourceReference, "sourceReference must not be null");
        this.peripherals = peripherals == null ? List.of() : List.copyOf(peripherals);

        Map<String, Stm8Peripheral> map = new HashMap<>();
        for (Stm8Peripheral p : this.peripherals) {
            if (map.put(p.name().toUpperCase(), p) != null) {
                throw new IllegalArgumentException("Duplicate peripheral name in pack: " + p.name());
            }
        }
        this.byName = Collections.unmodifiableMap(map);
    }

    public String packId() {
        return packId;
    }

    public String family() {
        return family;
    }

    public String schemaId() {
        return schemaId;
    }

    public String sourceReference() {
        return sourceReference;
    }

    public List<Stm8Peripheral> peripherals() {
        return peripherals;
    }

    public Optional<Stm8Peripheral> findPeripheral(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(byName.get(name.trim().toUpperCase()));
    }

    public Optional<Stm8Peripheral> findPeripheralAt(long address) {
        for (Stm8Peripheral p : peripherals) {
            if (p.containsAddress(address)) {
                return Optional.of(p);
            }
        }
        return Optional.empty();
    }

    public Optional<Stm8Register> findRegister(long address) {
        return findPeripheralAt(address).flatMap(p -> p.findRegisterAt(address));
    }

    public int totalRegisterCount() {
        return peripherals.stream().mapToInt(p -> p.registers().size()).sum();
    }
}
