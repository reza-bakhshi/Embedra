package io.github.rezabakhshi.embedra.ghidra.nordic;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.io.IOException;
import java.util.Objects;

/**
 * Checked exception for failures mapping Nordic nRF memory plans, vector tables, or peripherals into Ghidra.
 */
public final class NordicMappingException extends IOException {

    private static final long serialVersionUID = 1L;

    private final DiagnosticCode code;

    public NordicMappingException(DiagnosticCode code, String message) {
        super(message);
        this.code = Objects.requireNonNull(code, "code");
    }

    public NordicMappingException(DiagnosticCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = Objects.requireNonNull(code, "code");
    }

    public DiagnosticCode code() {
        return code;
    }
}
