package io.github.rezabakhshi.embedra.core.diagnostic;

import java.util.Objects;

/** Checked failure carrying the same typed diagnostic exposed to users. */
public final class DiagnosticException extends Exception {
    private static final long serialVersionUID = 1L;

    private final transient Diagnostic diagnostic;

    public DiagnosticException(Diagnostic diagnostic) {
        super(Objects.requireNonNull(diagnostic, "diagnostic").message());
        this.diagnostic = diagnostic;
    }

    public Diagnostic diagnostic() {
        return diagnostic;
    }
}
