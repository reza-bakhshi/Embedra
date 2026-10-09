package io.github.rezabakhshi.embedra.analyzers.logging;

/**
 * Expected argument type inferred from format specifiers (e.g. %s, %d, %x).
 */
public enum FormatArgumentType {
    STRING,
    INTEGER,
    HEX_INTEGER,
    POINTER,
    FLOAT,
    CHARACTER,
    CUSTOM,
    UNKNOWN
}
