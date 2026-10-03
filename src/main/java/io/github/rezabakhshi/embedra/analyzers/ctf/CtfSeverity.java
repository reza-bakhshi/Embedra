package io.github.rezabakhshi.embedra.analyzers.ctf;

/**
 * Severity ranking for discovered firmware entities and security leads (AN-006).
 */
public enum CtfSeverity {
    HIGH,
    MEDIUM,
    LOW,
    INFO;

    /**
     * Integer rank for sorting findings from highest to lowest severity.
     */
    public int rank() {
        return switch (this) {
            case HIGH -> 4;
            case MEDIUM -> 3;
            case LOW -> 2;
            case INFO -> 1;
        };
    }
}
