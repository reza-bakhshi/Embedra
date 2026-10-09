package io.github.rezabakhshi.embedra.analyzers.leads;

/**
 * Heuristic confidence ranking tier for candidate security leads (AN-005).
 */
public enum LeadConfidence {
    HIGH(3, "High", "Strong corroborated heuristic evidence with multiple contributing indicators"),
    MEDIUM(2, "Medium", "Plausible candidate with clear heuristic patterns and partial corroboration"),
    LOW(1, "Low", "Heuristic pattern match with limited corroborating context");

    private final int rank;

    private final String displayName;

    private final String description;

    LeadConfidence(int rank, String displayName, String description) {
        this.rank = rank;
        this.displayName = displayName;
        this.description = description;
    }

    public int rank() {
        return rank;
    }

    public String displayName() {
        return displayName;
    }

    public String description() {
        return description;
    }

    /**
     * Determines confidence tier from a normalized heuristic score (0.0 to 1.0).
     *
     * @param score heuristic score between 0.0 and 1.0
     * @return corresponding confidence level
     */
    public static LeadConfidence fromScore(double score) {
        if (score >= 0.75) {
            return HIGH;
        }
        if (score >= 0.45) {
            return MEDIUM;
        }
        return LOW;
    }
}
