package io.github.rezabakhshi.embedra.core;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;

/** Cooperative cancellation contract shared by pure operations. */
@FunctionalInterface
public interface CancellationToken {
    boolean isCancellationRequested();

    default void throwIfCancellationRequested() throws DiagnosticException {
        if (isCancellationRequested()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.CANCELLED, "Operation cancelled", null));
        }
    }

    static CancellationToken none() {
        return () -> false;
    }
}
