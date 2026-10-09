package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Result of comparing a string literal or stack string between two firmware workspaces (T062, AN-008).
 *
 * @param stringValue raw string value
 * @param changeKind change classification
 * @param sourceAddress address in baseline source (null if added)
 * @param targetAddress address in target (null if removed)
 * @param encoding character encoding
 * @param secret true if string represents sensitive credentials requiring redaction
 * @param details human-readable summary of differences
 */
public record StringDiffEntry(
        String stringValue,
        DiffChangeKind changeKind,
        Long sourceAddress,
        Long targetAddress,
        String encoding,
        boolean secret,
        String details) {

    public static final String REDACTED_SECRET = "[REDACTED_SECRET]";

    public StringDiffEntry {
        Objects.requireNonNull(stringValue, "stringValue must not be null");
        Objects.requireNonNull(changeKind, "changeKind must not be null");
        encoding = encoding == null ? "ASCII" : encoding;
        details = details == null ? "" : details;
    }

    /**
     * Returns the string representation, masked if secret and redaction is requested (AN-008).
     */
    public String maskedValue(boolean redactSecrets) {
        if (redactSecrets && secret) {
            return REDACTED_SECRET;
        }
        return stringValue;
    }
}
