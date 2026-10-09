package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Result of comparing a symbol between two firmware workspaces (T062).
 *
 * @param symbolName symbol name
 * @param symbolType symbol type classification
 * @param changeKind change classification
 * @param sourceAddress address in baseline source (null if added)
 * @param targetAddress address in target (null if removed)
 * @param sourceNamespace namespace in source
 * @param targetNamespace namespace in target
 * @param details human-readable summary of differences
 */
public record SymbolDiffEntry(
        String symbolName,
        String symbolType,
        DiffChangeKind changeKind,
        Long sourceAddress,
        Long targetAddress,
        String sourceNamespace,
        String targetNamespace,
        String details) {

    public SymbolDiffEntry {
        Objects.requireNonNull(symbolName, "symbolName must not be null");
        symbolType = symbolType == null ? "LABEL" : symbolType;
        Objects.requireNonNull(changeKind, "changeKind must not be null");
        sourceNamespace = sourceNamespace == null ? "" : sourceNamespace;
        targetNamespace = targetNamespace == null ? "" : targetNamespace;
        details = details == null ? "" : details;
    }
}
