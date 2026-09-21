package io.github.rezabakhshi.embedra.core.model;

import java.util.Objects;
import java.util.Set;

/** Symmetric-core or mutually exclusive boot-architecture grouping. */
public record ProcessorGroup(String id, ProcessorGroupKind kind, Set<String> memberNodeIds) {
    public ProcessorGroup {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        memberNodeIds = Set.copyOf(memberNodeIds);
        if (id.isBlank()) {
            throw new IllegalArgumentException("Processor-group ID must not be blank");
        }
        if (memberNodeIds.size() < 2) {
            throw new IllegalArgumentException("Processor groups require at least two members");
        }
    }
}
