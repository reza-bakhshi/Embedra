package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Result for an image's optional appended SHA-256 digest. */
public record EspImageHashEvidence(
        EspImageHashState state, Confidence confidence, List<Evidence> evidence) {
    public EspImageHashEvidence {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
