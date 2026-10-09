package io.github.rezabakhshi.embedra.analyzers.leads;

/**
 * Triage severity ranking for candidate security leads.
 */
public enum LeadSeverity {
    CRITICAL(5, "Critical"),
    HIGH(4, "High"),
    MEDIUM(3, "Medium"),
    LOW(2, "Low"),
    INFO(1, "Informational");

    private final int rank;

    private final String displayName;

    LeadSeverity(int rank, String displayName) {
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
