package io.github.rezabakhshi.embedra.targets;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Immutable provider classification and proposed mapping permissions. */
public record MemoryClassification(
        AddressRange range,
        MemoryRegionKind kind,
        boolean mappable,
        boolean readable,
        boolean writable,
        boolean executable,
        List<Evidence> evidence) {
    public MemoryClassification {
        Objects.requireNonNull(range, "range");
        Objects.requireNonNull(kind, "kind");
        evidence = List.copyOf(evidence);
        if (!mappable && (readable || writable || executable)) {
            throw new IllegalArgumentException("Unmappable memory cannot have permissions");
        }
        if (kind == MemoryRegionKind.UNKNOWN && mappable) {
            throw new IllegalArgumentException("Unknown memory cannot be mappable");
        }
    }
}
