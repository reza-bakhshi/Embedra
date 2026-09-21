package io.github.rezabakhshi.embedra.core.diagnostic;

/** Stable machine-readable diagnostic codes used by pure core operations. */
public enum DiagnosticCode {
    READ_OUT_OF_BOUNDS("CORE_READ_OUT_OF_BOUNDS"),
    LIMIT_EXCEEDED("CORE_LIMIT_EXCEEDED"),
    CANCELLED("CORE_CANCELLED"),
    INVALID_MODEL("CORE_INVALID_MODEL");

    private final String id;

    DiagnosticCode(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }
}
