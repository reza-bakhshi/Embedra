package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Result of comparing a partition or flash segment between two firmware workspaces (T062).
 *
 * @param partitionName partition name or label
 * @param changeKind change classification
 * @param partitionType partition type category
 * @param partitionSubtype partition subtype
 * @param sourceOffset physical offset in baseline source (null if added)
 * @param targetOffset physical offset in target (null if removed)
 * @param sourceSize byte length in baseline source
 * @param targetSize byte length in target
 * @param sourceFlags flags in baseline source
 * @param targetFlags flags in target
 * @param details human-readable summary of differences
 */
public record PartitionDiffEntry(
        String partitionName,
        DiffChangeKind changeKind,
        String partitionType,
        String partitionSubtype,
        Long sourceOffset,
        Long targetOffset,
        long sourceSize,
        long targetSize,
        String sourceFlags,
        String targetFlags,
        String details) {

    public PartitionDiffEntry {
        Objects.requireNonNull(partitionName, "partitionName must not be null");
        Objects.requireNonNull(changeKind, "changeKind must not be null");
        partitionType = partitionType == null ? "data" : partitionType;
        partitionSubtype = partitionSubtype == null ? "" : partitionSubtype;
        sourceFlags = sourceFlags == null ? "" : sourceFlags;
        targetFlags = targetFlags == null ? "" : targetFlags;
        details = details == null ? "" : details;
    }
}
