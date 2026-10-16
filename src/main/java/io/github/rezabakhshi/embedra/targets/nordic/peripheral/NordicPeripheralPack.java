package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Verified immutable collection of Nordic peripheral register definitions for an nRF series.
 */
public final class NordicPeripheralPack {

    private final String packId;

    private final String series;

    private final String schemaId;

    private final String sourceReference;

    private final List<NordicPeripheral> peripherals;

    private final Map<String, NordicPeripheral> byName;

    public NordicPeripheralPack(
            String packId,
            String series,
            String schemaId,
            String sourceReference,
            List<NordicPeripheral> peripherals) {
        this.packId = Objects.requireNonNull(packId, "packId must not be null");
        this.series = Objects.requireNonNull(series, "series must not be null");
        this.schemaId = Objects.requireNonNull(schemaId, "schemaId must not be null");
        this.sourceReference = Objects.requireNonNull(sourceReference, "sourceReference must not be null");
        this.peripherals = peripherals == null ? List.of() : List.copyOf(peripherals);

        Map<String, NordicPeripheral> map = new HashMap<>();
        for (NordicPeripheral p : this.peripherals) {
            if (map.put(p.name().toUpperCase(), p) != null) {
                throw new IllegalArgumentException("Duplicate peripheral name in pack: " + p.name());
            }
        }
        this.byName = Collections.unmodifiableMap(map);
    }

    public String packId() {
        return packId;
    }

    public String series() {
        return series;
    }

    public String schemaId() {
        return schemaId;
    }

    public String sourceReference() {
        return sourceReference;
    }

    public List<NordicPeripheral> peripherals() {
        return peripherals;
    }

    public Optional<NordicPeripheral> findPeripheral(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(byName.get(name.trim().toUpperCase()));
    }

    public Optional<NordicPeripheral> findPeripheralAt(long address) {
        for (NordicPeripheral p : peripherals) {
            if (p.containsAddress(address)) {
                return Optional.of(p);
            }
        }
        return Optional.empty();
    }

    public Optional<NordicRegister> findRegister(long address) {
        return findPeripheralAt(address).flatMap(p -> p.findRegisterAt(address));
    }

    public int totalRegisterCount() {
        return peripherals.stream().mapToInt(p -> p.registers().size()).sum();
    }

    public List<NordicRegister> easyDmaRegisters() {
        return peripherals.stream()
            .flatMap(p -> p.easyDmaRegisters().stream())
            .toList();
    }
}
