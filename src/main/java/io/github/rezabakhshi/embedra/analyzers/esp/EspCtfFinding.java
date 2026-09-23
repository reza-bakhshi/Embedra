package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Redacted ESP-specific CTF lead with stable code and explicit evidence. */
public record EspCtfFinding(
        String code,
        String severity,
        Confidence confidence,
        String explanation,
        Optional<SourceRange> sourceRange,
        boolean secret,
        List<Evidence> evidence) {
    public EspCtfFinding {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(confidence, "confidence");
        Objects.requireNonNull(explanation, "explanation");
        Objects.requireNonNull(sourceRange, "sourceRange");
        evidence = List.copyOf(evidence);
        if (!code.matches("ESP_[A-Z0-9_]+") || severity.isBlank()
            || explanation.isBlank()) {
            throw new IllegalArgumentException("Invalid ESP CTF finding");
        }
    }
}
