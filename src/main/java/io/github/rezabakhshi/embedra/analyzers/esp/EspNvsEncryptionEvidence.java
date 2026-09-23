package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** NVS encryption configuration evidence without exposing key material. */
public record EspNvsEncryptionEvidence(
        EspNvsEncryptionState state, Confidence confidence, List<Evidence> evidence) {
    public EspNvsEncryptionEvidence {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
