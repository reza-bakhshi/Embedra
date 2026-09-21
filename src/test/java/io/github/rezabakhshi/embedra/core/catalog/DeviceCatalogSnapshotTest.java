package io.github.rezabakhshi.embedra.core.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DeviceCatalogSnapshotTest {
    private static final CatalogSource SOURCE = new CatalogSource(
        "synthetic-vendor", "catalog-commit-1", "Apache-2.0", "synthetic test data");

    @Test
    void snapshotIsExactPartOrientedAndDeterministicallyOrdered() {
        DeviceCatalogSnapshot snapshot = DeviceCatalogSnapshot.create("synthetic", SOURCE,
            List.of(entry("part-b", "QFN", "EXPERIMENTAL"), entry("part-a", "BGA", "PLANNED")));

        assertEquals(List.of("part-a", "part-b"),
            snapshot.devices().stream().map(DeviceCatalogEntry::deviceId).toList());
        assertEquals(DeviceCatalogSnapshot.SCHEMA_ID, snapshot.schemaId());
        assertEquals(snapshot.toCanonicalJson(), DeviceCatalogSnapshot.create("synthetic", SOURCE,
            List.of(entry("part-a", "BGA", "PLANNED"), entry("part-b", "QFN", "EXPERIMENTAL")))
            .toCanonicalJson());
    }

    @Test
    void diffClassifiesAddedRemovedAndChangedExactParts() {
        DeviceCatalogSnapshot previous = DeviceCatalogSnapshot.create("synthetic", SOURCE,
            List.of(entry("part-a", "QFN", "PLANNED"), entry("part-removed", "QFN", "PLANNED")));
        DeviceCatalogSnapshot current = DeviceCatalogSnapshot.create("synthetic", SOURCE,
            List.of(entry("part-added", "BGA", "PLANNED"), entry("part-a", "QFN", "VERIFIED"),
                entry("part-unchanged", "QFN", "PLANNED")));
        previous = DeviceCatalogSnapshot.create("synthetic", SOURCE,
            List.of(entry("part-a", "QFN", "PLANNED"), entry("part-removed", "QFN", "PLANNED"),
                entry("part-unchanged", "QFN", "PLANNED")));

        DeviceCatalogDiff diff = current.diff(previous);

        assertEquals(List.of("part-added"), diff.added().stream().map(DeviceCatalogEntry::deviceId).toList());
        assertEquals(List.of("part-removed"), diff.removed().stream().map(DeviceCatalogEntry::deviceId).toList());
        assertEquals(List.of("part-a"), diff.changed().stream().map(DeviceCatalogChange::deviceId).toList());
        assertEquals(DeviceCatalogDiff.SCHEMA_ID, diff.schemaId());
    }

    @Test
    void snapshotRejectsDuplicateDeviceIdsAndInvalidSupportStates() {
        DeviceCatalogEntry duplicate = entry("part-a", "QFN", "PLANNED");

        assertThrows(IllegalArgumentException.class, () -> DeviceCatalogSnapshot.create(
            "synthetic", SOURCE, List.of(duplicate, duplicate)));
        assertThrows(IllegalArgumentException.class, () -> entry("part-a", "QFN", "NOT_A_STATE"));
        assertThrows(IllegalArgumentException.class, () -> new CatalogSource(
            "", "revision", "license", "provenance"));
        assertThrows(IllegalArgumentException.class, () -> new DeviceCatalogEntry(
            "part", "vendor", "family", "series", "part", "package", Map.of(), Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new DeviceCatalogEntry(
            "", "vendor", "family", "series", "part", "package", Map.of(),
            Map.of("feature", SupportState.PLANNED)));
        assertThrows(IllegalArgumentException.class, () -> new DeviceCatalogEntry(
            "part", "vendor", "family", "series", "part", "package", Map.of("", "value"),
            Map.of("feature", SupportState.PLANNED)));
        assertThrows(IllegalArgumentException.class, () -> new DeviceCatalogEntry(
            "part", "vendor", "family", "series", "part", "package", Map.of(),
            Map.of("", SupportState.PLANNED)));
        assertThrows(IllegalArgumentException.class, () -> new DeviceCatalogSnapshot(
            "wrong-schema", "synthetic", SOURCE, List.of(duplicate)));
        assertThrows(IllegalArgumentException.class, () -> new DeviceCatalogSnapshot(
            DeviceCatalogSnapshot.SCHEMA_ID, "", SOURCE, List.of(duplicate)));
        DeviceCatalogSnapshot other = DeviceCatalogSnapshot.create("other", SOURCE, List.of(duplicate));
        DeviceCatalogSnapshot snapshot = DeviceCatalogSnapshot.create("synthetic", SOURCE, List.of(duplicate));
        assertThrows(IllegalArgumentException.class, () -> snapshot.diff(other));
        assertThrows(IllegalArgumentException.class, () -> new DeviceCatalogDiff(
            "wrong", "synthetic", SOURCE, SOURCE, List.of(), List.of(), List.of()));
        assertThrows(IllegalArgumentException.class, () -> new DeviceCatalogDiff(
            DeviceCatalogDiff.SCHEMA_ID, "", SOURCE, SOURCE, List.of(), List.of(), List.of()));
        DeviceCatalogEntry changed = entry("part-a", "BGA", "PLANNED");
        assertThrows(IllegalArgumentException.class,
            () -> new DeviceCatalogChange("other", duplicate, changed));
        assertThrows(IllegalArgumentException.class,
            () -> new DeviceCatalogChange("part-a", duplicate,
                entry("other", "QFN", "PLANNED")));
        assertThrows(IllegalArgumentException.class,
            () -> new DeviceCatalogChange("part-a", duplicate, duplicate));
    }

    private static DeviceCatalogEntry entry(String id, String packageName, String state) {
        return new DeviceCatalogEntry(id, "Synthetic Vendor", "MCU", "Series-A", id,
            packageName, Map.of("isa", "synthetic-isa", "cores", "1"),
            Map.of("raw-import", SupportState.valueOf(state)));
    }
}
