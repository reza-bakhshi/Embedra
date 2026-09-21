package io.github.rezabakhshi.embedra.core.model;

import java.util.List;
import java.util.Objects;

/** Directed boot/reset relation retaining its mechanism and evidence. */
public record BootRelationship(
        String id,
        String sourceNodeId,
        String targetNodeId,
        BootRelationshipType type,
        String mechanism,
        Confidence confidence,
        List<Evidence> evidence) {
    public BootRelationship {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(sourceNodeId, "sourceNodeId");
        Objects.requireNonNull(targetNodeId, "targetNodeId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(mechanism, "mechanism");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
        if (id.isBlank() || sourceNodeId.isBlank() || targetNodeId.isBlank() || mechanism.isBlank()) {
            throw new IllegalArgumentException("Boot relationship fields must not be blank");
        }
        if (sourceNodeId.equals(targetNodeId)) {
            throw new IllegalArgumentException("A boot relationship requires two distinct nodes");
        }
    }
}
