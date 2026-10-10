package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

/**
 * Classification category of a cryptographic corpus evaluation sample (AN-015).
 */
public enum CryptoCorpusClassification {
    /**
     * Dedicated positive corpus containing known cryptographic primitives, hardware engine use,
     * ROM routines, constant tables, candidate keys, or certificates.
     */
    POSITIVE("Positive Crypto"),

    /**
     * Adversarial negative corpus containing non-crypto tables, high-entropy media/compression,
     * or non-crypto code idioms that must not be classified as encryption (AN-003).
     */
    NEGATIVE_ADVERSARIAL("Negative Adversarial"),

    /**
     * Explicitly modeled unsupported variant or customized algorithm to verify that "not found"
     * is recorded as an unsupported case and not confused with "not present" (AN-012, AN-015).
     */
    UNSUPPORTED_VARIANT("Unsupported Variant");

    private final String displayName;

    CryptoCorpusClassification(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
