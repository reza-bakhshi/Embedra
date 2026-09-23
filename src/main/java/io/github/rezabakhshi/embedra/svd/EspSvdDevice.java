package io.github.rezabakhshi.embedra.svd;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Immutable, provenance-bearing representation of an Espressif SVD device. */
public final class EspSvdDevice {
    private final String name;

    private final String sourceRevision;

    private final List<EspSvdPeripheral> peripherals;

    private final Map<String, EspSvdPeripheral> peripheralsByName;

    public EspSvdDevice(String name, String sourceRevision,
            List<EspSvdPeripheral> peripherals) {
        this.name = requireText(name, "device name");
        this.sourceRevision = requireText(sourceRevision, "source revision");
        this.peripherals = List.copyOf(peripherals);
        if (this.peripherals.isEmpty()) {
            throw new IllegalArgumentException("SVD device must contain peripherals");
        }
        Map<String, EspSvdPeripheral> indexed = new HashMap<>();
        for (EspSvdPeripheral peripheral : this.peripherals) {
            if (indexed.put(peripheral.name(), peripheral) != null) {
                throw new IllegalArgumentException("Duplicate SVD peripheral name");
            }
        }
        peripheralsByName = Map.copyOf(indexed);
    }

    public String name() {
        return name;
    }

    public String sourceRevision() {
        return sourceRevision;
    }

    public List<EspSvdPeripheral> peripherals() {
        return peripherals;
    }

    public EspSvdPeripheral requirePeripheral(String peripheralName) {
        EspSvdPeripheral peripheral = peripheralsByName.get(peripheralName);
        if (peripheral == null) {
            throw new IllegalArgumentException("Unknown SVD peripheral: " + peripheralName);
        }
        return peripheral;
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
