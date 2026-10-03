package io.github.rezabakhshi.embedra.ghidra.rp;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.io.IOException;
import java.util.Objects;

/**
 * Checked mapping failure for Raspberry Pi firmware with a stable diagnostic code.
 */
public final class RpMappingException extends IOException {

    private static final long serialVersionUID = 1L;

    private final DiagnosticCode code;

    public RpMappingException(DiagnosticCode code, String message) {
        super(message);
        this.code = Objects.requireNonNull(code, "code");
    }

    public RpMappingException(DiagnosticCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = Objects.requireNonNull(code, "code");
    }

    public DiagnosticCode code() {
        return code;
    }
}
