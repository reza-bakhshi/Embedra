package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Partition-table encryption indicators, not proof of the chip's eFuse state. */
public record EspFlashEncryptionEvidence(
        EspSecurityState state, List<String> partitionLabels,
        Confidence confidence, List<Evidence> evidence) {
    public EspFlashEncryptionEvidence {
        Objects.requireNonNull(state, "state");
        partitionLabels = partitionLabels.stream().sorted().toList();
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
