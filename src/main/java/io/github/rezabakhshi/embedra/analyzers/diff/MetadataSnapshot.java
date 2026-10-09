package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Immutable key-value metadata property of a firmware workspace (T062).
 *
 * @param key property name or identifier
 * @param value property value string
 * @param secret true if the property represents sensitive tokens requiring redaction
 */
public record MetadataSnapshot(
        String key,
        String value,
        boolean secret) {

    public MetadataSnapshot {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(value, "value must not be null");
    }

    public MetadataSnapshot(String key, String value) {
        this(key, value, false);
    }
}
