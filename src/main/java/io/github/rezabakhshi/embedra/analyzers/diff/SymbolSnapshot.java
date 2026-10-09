package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Immutable snapshot of a program symbol for workspace diffing (T062).
 *
 * @param name symbol name
 * @param address memory address of the symbol
 * @param type symbol type classification (e.g. FUNCTION, LABEL, PARAMETER, GLOBAL_VAR)
 * @param namespace parent namespace or class name
 */
public record SymbolSnapshot(
        String name,
        long address,
        String type,
        String namespace) {

    public SymbolSnapshot {
        Objects.requireNonNull(name, "name must not be null");
        type = type == null ? "LABEL" : type;
        namespace = namespace == null ? "Global" : namespace;
        if (address < 0) {
            throw new IllegalArgumentException("Address must be non-negative: " + address);
        }
    }
}
