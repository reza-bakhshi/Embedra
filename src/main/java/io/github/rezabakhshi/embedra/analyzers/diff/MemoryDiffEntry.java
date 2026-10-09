package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Result of comparing a memory block or region between two firmware workspaces (T062).
 *
 * @param blockName memory block name
 * @param changeKind change classification
 * @param sourceAddress start address in baseline source (null if added)
 * @param targetAddress start address in target (null if removed)
 * @param sourceSize size in baseline source
 * @param targetSize size in target
 * @param sourcePermissions permissions in baseline source
 * @param targetPermissions permissions in target
 * @param sourceHash content hash in baseline source
 * @param targetHash content hash in target
 * @param details human-readable summary of differences
 */
public record MemoryDiffEntry(
        String blockName,
        DiffChangeKind changeKind,
        Long sourceAddress,
        Long targetAddress,
        long sourceSize,
        long targetSize,
        String sourcePermissions,
        String targetPermissions,
        String sourceHash,
        String targetHash,
        String details) {

    public MemoryDiffEntry {
        Objects.requireNonNull(blockName, "blockName must not be null");
        Objects.requireNonNull(changeKind, "changeKind must not be null");
        sourcePermissions = sourcePermissions == null ? "" : sourcePermissions;
        targetPermissions = targetPermissions == null ? "" : targetPermissions;
        sourceHash = sourceHash == null ? "" : sourceHash;
        targetHash = targetHash == null ? "" : targetHash;
        details = details == null ? "" : details;
    }
}
