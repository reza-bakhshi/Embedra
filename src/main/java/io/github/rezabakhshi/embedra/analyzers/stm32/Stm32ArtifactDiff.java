package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.analyzers.esp.EspArtifactChangeKind;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/**
 * Deterministic content and location comparison of two STM32 firmware artifacts.
 *
 * <p>The change-kind vocabulary is the shared T025 diff contract
 * ({@link EspArtifactChangeKind}, reused unchanged): equal content digest at the
 * same extent is unchanged, an equal digest at another extent is moved, a
 * differing digest is modified, and a missing side is added or removed. The
 * comparison is a lead with provenance; it never proves device support or
 * exploitability.</p>
 */
public record Stm32ArtifactDiff(
        EspArtifactChangeKind kind, Confidence confidence, List<Evidence> evidence) {
    public Stm32ArtifactDiff {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
        if (evidence.isEmpty()) {
            throw new IllegalArgumentException("STM32 artifact diff requires evidence");
        }
    }
}
