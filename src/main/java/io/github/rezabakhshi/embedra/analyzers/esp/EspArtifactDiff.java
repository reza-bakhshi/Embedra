package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Deterministic factory/OTA content and physical-location comparison. */
public record EspArtifactDiff(
        EspArtifactChangeKind kind, Confidence confidence, List<Evidence> evidence) {
    public EspArtifactDiff {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
