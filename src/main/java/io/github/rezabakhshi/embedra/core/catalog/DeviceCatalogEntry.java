package io.github.rezabakhshi.embedra.core.catalog;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Exact silicon/package record with explicit per-capability support states. */
public record DeviceCatalogEntry(
        String deviceId,
        String vendor,
        String family,
        String series,
        String exactPart,
        String packageName,
        Map<String, String> attributes,
        Map<String, SupportState> supportStates) {
    public DeviceCatalogEntry {
        requireText(deviceId, "deviceId");
        requireText(vendor, "vendor");
        requireText(family, "family");
        requireText(series, "series");
        requireText(exactPart, "exactPart");
        requireText(packageName, "packageName");
        attributes = immutableSorted(attributes);
        supportStates = immutableSorted(supportStates);
        if (supportStates.isEmpty()) {
            throw new IllegalArgumentException("Every device needs at least one explicit support state");
        }
        if (attributes.keySet().stream().anyMatch(String::isBlank)
            || supportStates.keySet().stream().anyMatch(String::isBlank)) {
            throw new IllegalArgumentException("Catalog property names must not be blank");
        }
    }

    private static void requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }

    private static <T> Map<String, T> immutableSorted(Map<String, T> values) {
        return Collections.unmodifiableMap(new TreeMap<>(values));
    }
}
