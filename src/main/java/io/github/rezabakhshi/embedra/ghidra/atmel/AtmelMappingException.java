package io.github.rezabakhshi.embedra.ghidra.atmel;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.util.Objects;

/**
 * Checked exception thrown when an Atmel / Microchip firmware image fails format validation,
 * bounds checking, or Ghidra program mapping.
 */
public final class AtmelMappingException extends Exception {

    private static final long serialVersionUID = 1L;

    private final DiagnosticCode code;

    public AtmelMappingException(DiagnosticCode code, String message) {
        super(message);
        this.code = Objects.requireNonNull(code, "code must not be null");
    }

    public AtmelMappingException(DiagnosticCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = Objects.requireNonNull(code, "code must not be null");
    }

    public DiagnosticCode code() {
        return code;
    }
}
