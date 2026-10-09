package io.github.rezabakhshi.embedra.analyzers.logging;

/**
 * Diagnostic log level representing the severity or nature of a log, assert, or panic event (AN-004).
 */
public enum DiagnosticLogLevel {
    PANIC(1),
    ASSERT(2),
    ERROR(3),
    WARNING(4),
    INFO(5),
    DEBUG(6);

    private final int severityRank;

    DiagnosticLogLevel(int severityRank) {
        this.severityRank = severityRank;
    }

    public int severityRank() {
        return severityRank;
    }

    public boolean isCritical() {
        return this == PANIC || this == ASSERT || this == ERROR;
    }
}
