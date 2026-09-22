package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;

final class PackDiagnostics {
    private PackDiagnostics() {
    }

    static DiagnosticException failure(DiagnosticCode code, String message) {
        return new DiagnosticException(Diagnostic.error(code, message, null));
    }
}
