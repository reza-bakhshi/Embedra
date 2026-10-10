package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import java.util.Objects;

/**
 * Calibration metrics evaluating accuracy per confidence tier (AN-006, AN-010, AN-015).
 *
 * @param confidence confidence tier evaluated
 * @param totalFindings total number of findings produced at this confidence tier
 * @param truePositives count of corroborated, valid findings
 * @param falsePositives count of spurious, false findings
 */
public record ConfidenceCalibration(
        CryptoConfidence confidence,
        int totalFindings,
        int truePositives,
        int falsePositives) {

    public ConfidenceCalibration {
        Objects.requireNonNull(confidence, "confidence must not be null");
        if (totalFindings < 0 || truePositives < 0 || falsePositives < 0) {
            throw new IllegalArgumentException("Counts must be non-negative");
        }
    }

    /**
     * Precision of this confidence tier: TP / (TP + FP).
     * Returns 1.0 if total findings is 0.
     */
    public double precision() {
        if (totalFindings == 0) {
            return 1.0;
        }
        return (double) truePositives / totalFindings;
    }
}
