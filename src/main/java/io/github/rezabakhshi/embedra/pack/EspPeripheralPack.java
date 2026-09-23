package io.github.rezabakhshi.embedra.pack;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Verified immutable ESP peripheral-definition pack content. */
public final class EspPeripheralPack {
    private final PackManifest manifest;

    private final String deviceId;

    private final List<EspPeripheral> peripherals;

    private final Map<String, EspPeripheral> byName;

    public EspPeripheralPack(PackManifest manifest, String deviceId,
            List<EspPeripheral> peripherals) {
        this.manifest = Objects.requireNonNull(manifest, "manifest");
        PackManifest.requireIdentifier(deviceId, "device ID");
        this.deviceId = deviceId;
        this.peripherals = List.copyOf(peripherals);
        if (this.peripherals.isEmpty()) {
            throw new IllegalArgumentException("Peripheral pack must not be empty");
        }
        Map<String, EspPeripheral> indexed = new HashMap<>();
        for (EspPeripheral peripheral : this.peripherals) {
            index(indexed, peripheral.name(), peripheral);
            peripheral.aliases().forEach(alias -> index(indexed, alias, peripheral));
        }
        byName = Map.copyOf(indexed);
    }

    public PackManifest manifest() {
        return manifest;
    }

    public String deviceId() {
        return deviceId;
    }

    public List<EspPeripheral> peripherals() {
        return peripherals;
    }

    public long registerCount() {
        return peripherals.stream().mapToLong(peripheral -> peripheral.registers().size()).sum();
    }

    public EspPeripheral requirePeripheral(String name) {
        EspPeripheral peripheral = byName.get(name);
        if (peripheral == null) {
            throw new IllegalArgumentException("Unknown peripheral: " + name);
        }
        return peripheral;
    }

    private static void index(Map<String, EspPeripheral> index, String name,
            EspPeripheral peripheral) {
        EspPeripheral previous = index.put(name, peripheral);
        if (previous != null && previous != peripheral) {
            throw new IllegalArgumentException("Duplicate peripheral name or alias");
        }
    }
}
