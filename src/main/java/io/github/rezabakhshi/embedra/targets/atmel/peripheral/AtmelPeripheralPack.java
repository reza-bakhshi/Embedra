package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable verified peripheral pack containing hardware definitions for an Atmel/Microchip part.
 */
public final class AtmelPeripheralPack {

    private final String packId;

    private final String device;

    private final String catalogPart;

    private final String series;

    private final String core;

    private final String addressSpace;

    private final String schemaId;

    private final String sourceReference;

    private final List<AtmelIoPort> ioPorts;

    private final AtmelFuseMap fuseMap;

    private final List<AtmelInterrupt> interrupts;

    private final List<AtmelPeripheral> peripherals;

    private final Map<String, AtmelPeripheral> peripheralsByName;

    public AtmelPeripheralPack(
            String packId,
            String device,
            String catalogPart,
            String series,
            String core,
            String addressSpace,
            String schemaId,
            String sourceReference,
            List<AtmelIoPort> ioPorts,
            AtmelFuseMap fuseMap,
            List<AtmelInterrupt> interrupts,
            List<AtmelPeripheral> peripherals) {
        this.packId = Objects.requireNonNull(packId, "packId must not be null");
        this.device = Objects.requireNonNull(device, "device must not be null");
        this.catalogPart = Objects.requireNonNull(catalogPart, "catalogPart must not be null");
        this.series = Objects.requireNonNull(series, "series must not be null");
        this.core = Objects.requireNonNull(core, "core must not be null");
        this.addressSpace = Objects.requireNonNull(addressSpace, "addressSpace must not be null");
        this.schemaId = Objects.requireNonNull(schemaId, "schemaId must not be null");
        this.sourceReference = Objects.requireNonNull(sourceReference, "sourceReference must not be null");
        this.ioPorts = ioPorts == null ? List.of() : List.copyOf(ioPorts);
        this.fuseMap = Objects.requireNonNull(fuseMap, "fuseMap must not be null");
        this.interrupts = interrupts == null ? List.of() : List.copyOf(interrupts);
        this.peripherals = peripherals == null ? List.of() : List.copyOf(peripherals);

        Map<String, AtmelPeripheral> map = new HashMap<>();
        for (AtmelPeripheral p : this.peripherals) {
            map.put(p.name().toUpperCase(), p);
        }
        this.peripheralsByName = Collections.unmodifiableMap(map);
    }

    public String packId() {
        return packId;
    }

    public String device() {
        return device;
    }

    public String catalogPart() {
        return catalogPart;
    }

    public String series() {
        return series;
    }

    public String core() {
        return core;
    }

    public String addressSpace() {
        return addressSpace;
    }

    public String schemaId() {
        return schemaId;
    }

    public String sourceReference() {
        return sourceReference;
    }

    public List<AtmelIoPort> ioPorts() {
        return ioPorts;
    }

    public AtmelFuseMap fuseMap() {
        return fuseMap;
    }

    public List<AtmelInterrupt> interrupts() {
        return interrupts;
    }

    public List<AtmelPeripheral> peripherals() {
        return peripherals;
    }

    public Optional<AtmelPeripheral> findPeripheralByName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(peripheralsByName.get(name.trim().toUpperCase()));
    }

    public Optional<AtmelIoPort> findIoPortByName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        for (AtmelIoPort port : ioPorts) {
            if (port.name().equalsIgnoreCase(name.trim())) {
                return Optional.of(port);
            }
        }
        return Optional.empty();
    }

    public Optional<AtmelInterrupt> findInterruptByIndex(int index) {
        for (AtmelInterrupt intr : interrupts) {
            if (intr.index() == index) {
                return Optional.of(intr);
            }
        }
        return Optional.empty();
    }

    public Optional<AtmelInterrupt> findInterruptByName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        for (AtmelInterrupt intr : interrupts) {
            if (intr.name().equalsIgnoreCase(name.trim())) {
                return Optional.of(intr);
            }
        }
        return Optional.empty();
    }

    public int registerCount() {
        int count = 0;
        for (AtmelPeripheral p : peripherals) {
            count += p.registers().size();
        }
        return count;
    }

    public int bitfieldCount() {
        int count = 0;
        for (AtmelPeripheral p : peripherals) {
            for (AtmelRegister r : p.registers()) {
                count += r.bitfields().size();
            }
        }
        return count;
    }
}
