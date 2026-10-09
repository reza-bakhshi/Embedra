package io.github.rezabakhshi.embedra.analyzers.findings;

/**
 * Confidence ranking tiers for unified findings (AN-006).
 */
public enum FindingConfidence {
    CONFIRMED(4, "Confirmed"),
    LIKELY(3, "Likely"),
    PLAUSIBLE(2, "Plausible"),
    LEAD(1, "Lead");

    private final int rank;

    private final String displayName;

    FindingConfidence(int rank, String displayName) {
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
