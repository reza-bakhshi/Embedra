package io.github.rezabakhshi.embedra.ghidra.stm8;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.io.IOException;
import java.util.Objects;

/**
 * Checked exception for failures mapping STM8 memory plans, vector tables, or peripherals into Ghidra.
 */
public final class Stm8MappingException extends IOException {

    private static final long serialVersionUID = 1L;

    private final DiagnosticCode code;

    public Stm8MappingException(DiagnosticCode code, String message) {
        super(message);
        this.code = Objects.requireNonNull(code, "code");
    }

    public Stm8MappingException(DiagnosticCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = Objects.requireNonNull(code, "code");
    }

    public DiagnosticCode code() {
        return code;
    }
}
