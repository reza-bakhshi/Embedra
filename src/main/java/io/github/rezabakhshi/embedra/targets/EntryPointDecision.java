package io.github.rezabakhshi.embedra.targets;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Provider decision for creating one entry point after mapping validation. */
public record EntryPointDecision(
        boolean accepted,
        long address,
        String reason,
        Optional<MemoryClassification> classification,
        List<Evidence> evidence) {
    public EntryPointDecision {
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(classification, "classification");
        evidence = List.copyOf(evidence);
        if (address < 0 || reason.isBlank() || (accepted && classification.isEmpty())) {
            throw new IllegalArgumentException("Entry-point decision is inconsistent");
        }
    }
}
