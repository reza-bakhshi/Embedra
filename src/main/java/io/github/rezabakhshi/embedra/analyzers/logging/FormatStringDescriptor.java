package io.github.rezabakhshi.embedra.analyzers.logging;

import java.util.List;
import java.util.Objects;

/**
 * Describes a parsed format string, including its specifiers and expected arguments (AN-004).
 *
 * @param rawText raw format string text
 * @param specifiers list of parsed format specifiers
 * @param expectedArgumentCount total number of expected arguments
 * @param argumentTypes inferred types for expected arguments in order
 */
public record FormatStringDescriptor(
        String rawText,
        List<FormatSpecifier> specifiers,
        int expectedArgumentCount,
        List<FormatArgumentType> argumentTypes) {

    public FormatStringDescriptor {
        Objects.requireNonNull(rawText, "rawText must not be null");
        specifiers = specifiers == null ? List.of() : List.copyOf(specifiers);
        argumentTypes = argumentTypes == null ? List.of() : List.copyOf(argumentTypes);
        if (expectedArgumentCount < 0) {
            throw new IllegalArgumentException("expectedArgumentCount must not be negative");
        }
    }

    public static FormatStringDescriptor empty() {
        return new FormatStringDescriptor("", List.of(), 0, List.of());
    }

    public static FormatStringDescriptor plain(String rawText) {
        return new FormatStringDescriptor(rawText, List.of(), 0, List.of());
    }

    public boolean hasSpecifiers() {
        return !specifiers.isEmpty();
    }
}
