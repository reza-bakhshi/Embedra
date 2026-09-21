package io.github.rezabakhshi.embedra.core.diagnostic;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;
import java.util.Optional;

/** Immutable diagnostic with a stable code and optional source location. */
public record Diagnostic(
        DiagnosticCode code,
        DiagnosticSeverity severity,
        String message,
        Optional<SourceRange> sourceRange) {
    public Diagnostic {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(sourceRange, "sourceRange");
        if (message.isBlank()) {
            throw new IllegalArgumentException("Diagnostic message must not be blank");
        }
    }

    public static Diagnostic error(DiagnosticCode code, String message, SourceRange sourceRange) {
        return new Diagnostic(code, DiagnosticSeverity.ERROR, message, Optional.ofNullable(sourceRange));
    }
}
