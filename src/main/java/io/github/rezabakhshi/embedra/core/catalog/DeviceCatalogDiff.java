package io.github.rezabakhshi.embedra.core.catalog;

import io.github.rezabakhshi.embedra.core.report.CanonicalJson;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Deterministic exact-device additions, removals, and property/state changes. */
public record DeviceCatalogDiff(
        String schemaId,
        String catalogId,
        CatalogSource previousSource,
        CatalogSource currentSource,
        List<DeviceCatalogEntry> added,
        List<DeviceCatalogEntry> removed,
        List<DeviceCatalogChange> changed) {
    public static final String SCHEMA_ID = "urn:embedra:schema:device-catalog-diff:1";

    public DeviceCatalogDiff {
        Objects.requireNonNull(schemaId, "schemaId");
        Objects.requireNonNull(catalogId, "catalogId");
        Objects.requireNonNull(previousSource, "previousSource");
        Objects.requireNonNull(currentSource, "currentSource");
        added = added.stream().sorted(Comparator.comparing(DeviceCatalogEntry::deviceId)).toList();
        removed = removed.stream().sorted(Comparator.comparing(DeviceCatalogEntry::deviceId)).toList();
        changed = changed.stream().sorted(Comparator.comparing(DeviceCatalogChange::deviceId)).toList();
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new IllegalArgumentException("Unsupported device-catalog diff schema: " + schemaId);
        }
        if (catalogId.isBlank()) {
            throw new IllegalArgumentException("Catalog ID must not be blank");
        }
    }

    static DeviceCatalogDiff create(
            String catalogId,
            CatalogSource previousSource,
            CatalogSource currentSource,
            List<DeviceCatalogEntry> added,
            List<DeviceCatalogEntry> removed,
            List<DeviceCatalogChange> changed) {
        return new DeviceCatalogDiff(SCHEMA_ID, catalogId, previousSource, currentSource,
            added, removed, changed);
    }

    public String toCanonicalJson() {
        return CanonicalJson.write(Map.of(
            "schemaId", schemaId,
            "catalogId", catalogId,
            "previousSource", DeviceCatalogSnapshot.sourceValue(previousSource),
            "currentSource", DeviceCatalogSnapshot.sourceValue(currentSource),
            "added", added.stream().map(DeviceCatalogSnapshot::entryValue).toList(),
            "removed", removed.stream().map(DeviceCatalogSnapshot::entryValue).toList(),
            "changed", changed.stream().map(change -> Map.of(
                "deviceId", change.deviceId(),
                "previous", DeviceCatalogSnapshot.entryValue(change.previous()),
                "current", DeviceCatalogSnapshot.entryValue(change.current()))).toList()));
    }
}
