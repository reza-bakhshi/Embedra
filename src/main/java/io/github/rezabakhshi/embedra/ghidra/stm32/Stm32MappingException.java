package io.github.rezabakhshi.embedra.ghidra.stm32;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.io.IOException;
import java.util.Objects;

/** Checked STM32 enrichment failure with a stable machine-readable code. */
public final class Stm32MappingException extends IOException {
    private static final long serialVersionUID = 1L;

    private final DiagnosticCode code;

    public Stm32MappingException(DiagnosticCode code, String message) {
        super(message);
        this.code = Objects.requireNonNull(code, "code");
    }

    public Stm32MappingException(DiagnosticCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = Objects.requireNonNull(code, "code");
    }

    public DiagnosticCode code() {
        return code;
    }
}
