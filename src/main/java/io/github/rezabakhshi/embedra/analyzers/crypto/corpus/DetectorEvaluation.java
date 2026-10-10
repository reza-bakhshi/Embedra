package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Statistical benchmark evaluation metrics for an individual detection engine (AN-015).
 *
 * @param detectorType detection engine evaluated
 * @param truePositives number of correctly identified cryptographic implementations/features
 * @param falsePositives number of incorrectly identified non-crypto or spurious findings
 * @param trueNegatives number of correctly rejected non-crypto or irrelevant samples
 * @param falseNegatives number of missed cryptographic implementations/features
 * @param confidenceDistribution distribution of findings across confidence tiers
 */
public record DetectorEvaluation(
        CryptoDetectorType detectorType,
        int truePositives,
        int falsePositives,
        int trueNegatives,
        int falseNegatives,
        Map<CryptoConfidence, Integer> confidenceDistribution) {

    public DetectorEvaluation {
        Objects.requireNonNull(detectorType, "detectorType must not be null");
        if (truePositives < 0 || falsePositives < 0 || trueNegatives < 0 || falseNegatives < 0) {
            throw new IllegalArgumentException("Counts must be non-negative");
        }
        confidenceDistribution = confidenceDistribution == null
                ? Map.of() : Collections.unmodifiableMap(Map.copyOf(confidenceDistribution));
    }

    /**
     * Computes detector precision: TP / (TP + FP).
     * Returns 1.0 if TP + FP == 0.
     */
    public double precision() {
        int totalPredictedPositive = truePositives + falsePositives;
        if (totalPredictedPositive == 0) {
            return 1.0;
        }
        return (double) truePositives / totalPredictedPositive;
    }

    /**
     * Computes detector recall: TP / (TP + FN).
     * Returns 1.0 if TP + FN == 0.
     */
    public double recall() {
        int totalActualPositive = truePositives + falseNegatives;
        if (totalActualPositive == 0) {
            return 1.0;
        }
        return (double) truePositives / totalActualPositive;
    }

    /**
     * Computes detector false-positive rate (FPR): FP / (FP + TN).
     * Returns 0.0 if FP + TN == 0.
     */
    public double falsePositiveRate() {
        int totalActualNegative = falsePositives + trueNegatives;
        if (totalActualNegative == 0) {
            return 0.0;
        }
        return (double) falsePositives / totalActualNegative;
    }

    /**
     * Computes detector F1 score: 2 * (Precision * Recall) / (Precision + Recall).
     * Returns 0.0 if Precision + Recall == 0.
     */
    public double f1Score() {
        double prec = precision();
        double rec = recall();
        if (prec + rec == 0.0) {
            return 0.0;
        }
        return (2.0 * prec * rec) / (prec + rec);
    }
}
