package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Exact resolved FreeRTOS symbol, not a claim inferred from a string. */
public record EspFreeRtosEvidence(
        String name, long address, EspSymbolFactKind kind,
        Confidence confidence, List<Evidence> evidence) {
    public EspFreeRtosEvidence {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
