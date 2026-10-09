package io.github.rezabakhshi.embedra.analyzers.crypto;

/**
 * Confidence ranking for cryptographic analysis findings (AN-006, AN-010).
 */
public enum CryptoConfidence {
    /**
     * Confirmed detection supported by multiple corroborating evidence layers or exact full table match.
     */
    CONFIRMED("Confirmed"),

    /**
     * Likely detection based on strong table signature or single high-fidelity evidence layer.
     */
    LIKELY("Likely"),

    /**
     * Plausible hypothesis requiring further context or corroboration.
     */
    PLAUSIBLE("Plausible"),

    /**
     * Initial detection lead (e.g. peripheral register access or high entropy without known structure).
     */
    LEAD("Lead");

    private final String displayName;

    CryptoConfidence(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
