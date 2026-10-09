package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Result of comparing metadata properties between two firmware workspaces (T062).
 *
 * @param propertyKey property name or key
 * @param changeKind change classification
 * @param sourceValue value in baseline source (null if added)
 * @param targetValue value in target (null if removed)
 * @param secret true if property value contains sensitive material
 * @param details human-readable summary of differences
 */
public record MetadataDiffEntry(
        String propertyKey,
        DiffChangeKind changeKind,
        String sourceValue,
        String targetValue,
        boolean secret,
        String details) {

    public static final String REDACTED_SECRET = "[REDACTED_SECRET]";

    public MetadataDiffEntry {
        Objects.requireNonNull(propertyKey, "propertyKey must not be null");
        Objects.requireNonNull(changeKind, "changeKind must not be null");
        details = details == null ? "" : details;
    }

    public MetadataDiffEntry(
            String propertyKey,
            DiffChangeKind changeKind,
            String sourceValue,
            String targetValue,
            String details) {
        this(propertyKey, changeKind, sourceValue, targetValue, false, details);
    }

    public String maskedSourceValue(boolean redactSecrets) {
        if (sourceValue == null) {
            return null;
        }
        return (redactSecrets && secret) ? REDACTED_SECRET : sourceValue;
    }

    public String maskedTargetValue(boolean redactSecrets) {
        if (targetValue == null) {
            return null;
        }
        return (redactSecrets && secret) ? REDACTED_SECRET : targetValue;
    }
}
