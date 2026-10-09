package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Result of comparing a function between two firmware workspaces (T062).
 *
 * @param functionName function name or label
 * @param changeKind change classification
 * @param sourceAddress entry point in baseline source (null if added)
 * @param targetAddress entry point in target (null if removed)
 * @param sourceLength byte size in baseline source
 * @param targetLength byte size in target
 * @param sourceHash body hash in baseline source
 * @param targetHash body hash in target
 * @param details human-readable summary of differences
 */
public record FunctionDiffEntry(
        String functionName,
        DiffChangeKind changeKind,
        Long sourceAddress,
        Long targetAddress,
        long sourceLength,
        long targetLength,
        String sourceHash,
        String targetHash,
        String details) {

    public FunctionDiffEntry {
        Objects.requireNonNull(functionName, "functionName must not be null");
        Objects.requireNonNull(changeKind, "changeKind must not be null");
        sourceHash = sourceHash == null ? "" : sourceHash;
        targetHash = targetHash == null ? "" : targetHash;
        details = details == null ? "" : details;
    }
}
