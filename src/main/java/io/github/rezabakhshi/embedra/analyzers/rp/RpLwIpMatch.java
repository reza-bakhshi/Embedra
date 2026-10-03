package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Result of detecting lwIP protocol stack components and state models.
 */
public record RpLwIpMatch(
        boolean detected,
        Optional<String> version,
        List<String> protocols,
        List<String> apis,
        Confidence confidence,
        List<Evidence> evidence) {

    public RpLwIpMatch {
        Objects.requireNonNull(version, "version must not be null");
        Objects.requireNonNull(protocols, "protocols must not be null");
        Objects.requireNonNull(apis, "apis must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        Objects.requireNonNull(evidence, "evidence must not be null");
        protocols = List.copyOf(protocols);
        apis = List.copyOf(apis);
        evidence = List.copyOf(evidence);
    }

    public static RpLwIpMatch notDetected() {
        return new RpLwIpMatch(false, Optional.empty(), List.of(), List.of(), Confidence.UNKNOWN, List.of());
    }
}
