package io.github.rezabakhshi.embedra.analyzers.findings;

/**
 * Triage severity ranking for unified findings (AN-006).
 */
public enum FindingSeverity {
    CRITICAL(5, "Critical"),
    HIGH(4, "High"),
    MEDIUM(3, "Medium"),
    LOW(2, "Low"),
    INFO(1, "Informational");

    private final int rank;

    private final String displayName;

    FindingSeverity(int rank, String displayName) {
        this.rank = rank;
        this.displayName = displayName;
    }

    public int rank() {
        return rank;
    }

    public String displayName() {
        return displayName;
    }
}
