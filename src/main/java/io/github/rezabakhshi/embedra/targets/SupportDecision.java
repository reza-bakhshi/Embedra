package io.github.rezabakhshi.embedra.targets;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Provider support result that never substitutes a family guess for exact identity. */
public record SupportDecision(
        boolean supported,
        Optional<String> deviceId,
        String reason,
        List<Evidence> evidence) {
    public SupportDecision {
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(reason, "reason");
        evidence = List.copyOf(evidence);
        if (reason.isBlank() || supported != deviceId.isPresent()) {
            throw new IllegalArgumentException("Support decision is inconsistent");
        }
    }
}
