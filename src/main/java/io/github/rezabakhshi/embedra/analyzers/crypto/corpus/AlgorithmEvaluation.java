package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import java.util.Objects;

/**
 * Statistical benchmark evaluation metrics for an individual cryptographic algorithm or format (AN-012, AN-015).
 *
 * @param algorithm cryptographic algorithm evaluated
 * @param truePositives number of correctly identified instances
 * @param falsePositives number of falsely attributed instances
 * @param trueNegatives number of correctly rejected non-matching instances
 * @param falseNegatives number of missed instances
 */
public record AlgorithmEvaluation(
        CryptoAlgorithm algorithm,
        int truePositives,
        int falsePositives,
        int trueNegatives,
        int falseNegatives) {

    public AlgorithmEvaluation {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        if (truePositives < 0 || falsePositives < 0 || trueNegatives < 0 || falseNegatives < 0) {
            throw new IllegalArgumentException("Counts must be non-negative");
        }
    }

    /**
     * Computes algorithm precision: TP / (TP + FP).
     * Returns 1.0 if TP + FP == 0.
     */
    public double precision() {
        int totalPredicted = truePositives + falsePositives;
        if (totalPredicted == 0) {
            return 1.0;
        }
        return (double) truePositives / totalPredicted;
    }

    /**
     * Computes algorithm recall: TP / (TP + FN).
     * Returns 1.0 if TP + FN == 0.
     */
    public double recall() {
        int totalActual = truePositives + falseNegatives;
        if (totalActual == 0) {
            return 1.0;
        }
        return (double) truePositives / totalActual;
    }

    /**
     * Computes algorithm false-positive rate (FPR): FP / (FP + TN).
     * Returns 0.0 if FP + TN == 0.
     */
    public double falsePositiveRate() {
        int totalNegative = falsePositives + trueNegatives;
        if (totalNegative == 0) {
            return 0.0;
        }
        return (double) falsePositives / totalNegative;
    }

    /**
     * Computes algorithm F1 score: 2 * (Precision * Recall) / (Precision + Recall).
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
