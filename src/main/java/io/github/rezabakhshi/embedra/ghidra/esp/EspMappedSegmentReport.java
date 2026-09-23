package io.github.rezabakhshi.embedra.ghidra.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import java.util.Objects;

/** Immutable report entry for one committed ESP segment mapping. */
public record EspMappedSegmentReport(
        int index,
        String blockName,
        long loadAddress,
        long length,
        SourceRange sourceRange,
        MemoryRegionKind kind,
        boolean readable,
        boolean writable,
        boolean executable) {
    public EspMappedSegmentReport {
        Objects.requireNonNull(blockName, "blockName");
        Objects.requireNonNull(sourceRange, "sourceRange");
        Objects.requireNonNull(kind, "kind");
        if (index < 0 || blockName.isBlank() || loadAddress < 0 || length <= 0
            || sourceRange.length() != length) {
            throw new IllegalArgumentException("Mapped segment report is inconsistent");
        }
    }
}
