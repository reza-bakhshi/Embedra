package io.github.rezabakhshi.embedra.core.model;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Shared memory, its aliases, accessors, confidence, and provenance. */
public record SharedMemoryRegion(
        String id,
        AddressRange range,
        Set<String> ownerNodeIds,
        Set<String> readerNodeIds,
        Set<String> writerNodeIds,
        List<AddressRange> aliases,
        Confidence confidence,
        List<Evidence> evidence) {
    public SharedMemoryRegion {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(range, "range");
        Objects.requireNonNull(confidence, "confidence");
        ownerNodeIds = Set.copyOf(ownerNodeIds);
        readerNodeIds = Set.copyOf(readerNodeIds);
        writerNodeIds = Set.copyOf(writerNodeIds);
        aliases = List.copyOf(aliases);
        evidence = List.copyOf(evidence);
        if (id.isBlank()) {
            throw new IllegalArgumentException("Shared-memory ID must not be blank");
        }
        if (aliases.stream().anyMatch(alias -> alias.length() != range.length())) {
            throw new IllegalArgumentException("A memory alias must preserve the region length");
        }
    }

    public Set<String> referencedProcessorIds() {
        java.util.HashSet<String> result = new java.util.HashSet<>(ownerNodeIds);
        result.addAll(readerNodeIds);
        result.addAll(writerNodeIds);
        return Set.copyOf(result);
    }
}
