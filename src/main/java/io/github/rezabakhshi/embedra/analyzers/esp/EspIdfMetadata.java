package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** ESP-IDF build metadata; an absent version is explicitly unknown. */
public record EspIdfMetadata(
        Optional<String> idfVersion, Optional<String> projectName,
        Optional<String> projectVersion, Confidence confidence, List<Evidence> evidence) {
    public EspIdfMetadata {
        Objects.requireNonNull(idfVersion, "idfVersion");
        Objects.requireNonNull(projectName, "projectName");
        Objects.requireNonNull(projectVersion, "projectVersion");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
