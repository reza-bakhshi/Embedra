package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import java.util.Objects;

/** One provider-owned address range consumed by the neutral ESP memory service. */
public record EspMemoryRegion(
        MemoryRegionKind kind,
        long start,
        long endExclusive,
        boolean readable,
        boolean writable,
        boolean executable,
        Evidence evidence) {
    public EspMemoryRegion {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(evidence, "evidence");
        if (kind == MemoryRegionKind.UNKNOWN || start < 0 || endExclusive <= start) {
            throw new IllegalArgumentException("ESP memory region must be concrete and non-empty");
        }
    }
}
