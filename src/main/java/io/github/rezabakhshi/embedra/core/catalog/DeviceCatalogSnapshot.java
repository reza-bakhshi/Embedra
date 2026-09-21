package io.github.rezabakhshi.embedra.core.catalog;

import io.github.rezabakhshi.embedra.core.report.CanonicalJson;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Deterministic snapshot of exact device records from one versioned source. */
public record DeviceCatalogSnapshot(
        String schemaId, String catalogId, CatalogSource source, List<DeviceCatalogEntry> devices) {
    public static final String SCHEMA_ID = "urn:embedra:schema:device-catalog-snapshot:1";

    public DeviceCatalogSnapshot {
        Objects.requireNonNull(schemaId, "schemaId");
        Objects.requireNonNull(catalogId, "catalogId");
        Objects.requireNonNull(source, "source");
        devices = devices.stream().sorted(Comparator.comparing(DeviceCatalogEntry::deviceId)).toList();
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new IllegalArgumentException("Unsupported device-catalog snapshot schema: " + schemaId);
        }
        if (catalogId.isBlank()) {
            throw new IllegalArgumentException("Catalog ID must not be blank");
        }
        if (new HashSet<>(devices.stream().map(DeviceCatalogEntry::deviceId).toList()).size()
            != devices.size()) {
            throw new IllegalArgumentException("Duplicate exact device ID in catalog snapshot");
        }
    }

    public static DeviceCatalogSnapshot create(
            String catalogId, CatalogSource source, List<DeviceCatalogEntry> devices) {
        return new DeviceCatalogSnapshot(SCHEMA_ID, catalogId, source, devices);
    }

    public DeviceCatalogDiff diff(DeviceCatalogSnapshot previous) {
        Objects.requireNonNull(previous, "previous");
        if (!catalogId.equals(previous.catalogId)) {
            throw new IllegalArgumentException("Catalog snapshots must have the same catalog ID");
        }
        Map<String, DeviceCatalogEntry> oldById = index(previous.devices);
        Map<String, DeviceCatalogEntry> newById = index(devices);
        List<DeviceCatalogEntry> added = new ArrayList<>();
        List<DeviceCatalogEntry> removed = new ArrayList<>();
        List<DeviceCatalogChange> changed = new ArrayList<>();
        for (DeviceCatalogEntry current : devices) {
            DeviceCatalogEntry old = oldById.get(current.deviceId());
            if (old == null) {
                added.add(current);
            }
            else if (!old.equals(current)) {
                changed.add(new DeviceCatalogChange(current.deviceId(), old, current));
            }
        }
        for (DeviceCatalogEntry old : previous.devices) {
            if (!newById.containsKey(old.deviceId())) {
                removed.add(old);
            }
        }
        return DeviceCatalogDiff.create(catalogId, previous.source, source, added, removed, changed);
    }

    public String toCanonicalJson() {
        return CanonicalJson.write(canonicalValue());
    }

    Map<String, Object> canonicalValue() {
        return Map.of(
            "schemaId", schemaId,
            "catalogId", catalogId,
            "source", sourceValue(source),
            "devices", devices.stream().map(DeviceCatalogSnapshot::entryValue).toList());
    }

    static Map<String, Object> entryValue(DeviceCatalogEntry entry) {
        HashMap<String, Object> states = new HashMap<>();
        entry.supportStates().forEach((key, value) -> states.put(key, value.name()));
        return Map.of(
            "deviceId", entry.deviceId(),
            "vendor", entry.vendor(),
            "family", entry.family(),
            "series", entry.series(),
            "exactPart", entry.exactPart(),
            "package", entry.packageName(),
            "attributes", entry.attributes(),
            "supportStates", states);
    }

    static Map<String, Object> sourceValue(CatalogSource source) {
        return Map.of(
            "identity", source.identity(),
            "revision", source.revision(),
            "license", source.license(),
            "provenance", source.provenance());
    }

    private static Map<String, DeviceCatalogEntry> index(List<DeviceCatalogEntry> devices) {
        HashMap<String, DeviceCatalogEntry> result = new HashMap<>();
        devices.forEach(device -> result.put(device.deviceId(), device));
        return result;
    }
}
