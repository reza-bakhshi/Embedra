package io.github.rezabakhshi.embedra.analyzers.logging;

import java.util.Objects;

/**
 * Represents a single format specifier within a format string (e.g. "%02X", "%s", "%d").
 *
 * @param index zero-based index of this specifier in the format string
 * @param specifierText full text of the specifier (e.g. "%02X", "%1$s")
 * @param type inferred argument type
 * @param width optional field width (-1 if unspecified)
 * @param precision optional precision (-1 if unspecified)
 * @param isPositional whether positional indexing is used (e.g. "%1$s")
 * @param positionalIndex 1-based positional index (-1 if non-positional)
 */
public record FormatSpecifier(
        int index,
        String specifierText,
        FormatArgumentType type,
        int width,
        int precision,
        boolean isPositional,
        int positionalIndex) {

    public FormatSpecifier {
        Objects.requireNonNull(specifierText, "specifierText must not be null");
        Objects.requireNonNull(type, "type must not be null");
        if (index < 0) {
            throw new IllegalArgumentException("index must not be negative");
        }
    }
}
