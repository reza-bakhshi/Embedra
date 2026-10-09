package io.github.rezabakhshi.embedra.analyzers.crypto.entropy;

/**
 * Metric summary of an entropy window calculation.
 *
 * @param entropy Shannon entropy in bits per byte [0.0, 8.0]
 * @param chiSquared Pearson chi-squared goodness-of-fit against a uniform distribution
 * @param highEntropy true if entropy meets or exceeds high-entropy threshold (>= 7.2)
 * @param likelyCompressed true if byte signatures or frequency biases suggest compression rather than encryption
 * @param likelyCiphertext true if uniform distribution and high entropy indicate cryptographic ciphertext
 */
public record EntropyResult(
        double entropy,
        double chiSquared,
        boolean highEntropy,
        boolean likelyCompressed,
        boolean likelyCiphertext) {

    public EntropyResult {
        if (entropy < 0.0 || entropy > 8.0) {
            throw new IllegalArgumentException("Entropy must be in [0.0, 8.0]: " + entropy);
        }
    }
}
