package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Immutable snapshot of a recovered firmware string literal or stack string (T062, AN-008).
 *
 * @param value decoded string text
 * @param address memory address or offset where the string is located
 * @param encoding text character encoding (e.g. ASCII, UTF-8, UTF-16)
 * @param secret true if the string represents sensitive credentials requiring redaction
 */
public record StringSnapshot(
        String value,
        long address,
        String encoding,
        boolean secret) {

    public StringSnapshot {
        Objects.requireNonNull(value, "value must not be null");
        encoding = encoding == null ? "ASCII" : encoding;
        if (address < 0) {
            throw new IllegalArgumentException("Address must be non-negative: " + address);
        }
    }
}
