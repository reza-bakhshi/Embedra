package io.github.rezabakhshi.embedra.analyzers.crypto;

/**
 * Configuration options for the layered cryptographic analysis pipeline.
 */
public record CryptoScanOptions(
        boolean scanTables,
        boolean scanEntropy,
        boolean scanKeys,
        boolean scanSignatures,
        boolean scanHardware,
        boolean scanNonCryptoEncodings,
        double entropyThreshold,
        int minKeyLength,
        int maxKeyLength) {

    public CryptoScanOptions {
        if (entropyThreshold <= 0.0 || entropyThreshold > 8.0) {
            throw new IllegalArgumentException("Entropy threshold must be in (0.0, 8.0]: " + entropyThreshold);
        }
        if (minKeyLength <= 0 || maxKeyLength < minKeyLength) {
            throw new IllegalArgumentException("Invalid key lengths: min=" + minKeyLength + ", max=" + maxKeyLength);
        }
    }

    public CryptoScanOptions(
            boolean scanTables,
            boolean scanEntropy,
            boolean scanKeys,
            boolean scanSignatures,
            boolean scanNonCryptoEncodings,
            double entropyThreshold,
            int minKeyLength,
            int maxKeyLength) {
        this(scanTables, scanEntropy, scanKeys, scanSignatures, true, scanNonCryptoEncodings,
                entropyThreshold, minKeyLength, maxKeyLength);
    }

    public CryptoScanOptions(
            boolean scanTables,
            boolean scanEntropy,
            boolean scanKeys,
            boolean scanNonCryptoEncodings,
            double entropyThreshold,
            int minKeyLength,
            int maxKeyLength) {
        this(scanTables, scanEntropy, scanKeys, true, true, scanNonCryptoEncodings,
                entropyThreshold, minKeyLength, maxKeyLength);
    }

    public static CryptoScanOptions defaults() {
        return new CryptoScanOptions(
                true,   // scanTables
                true,   // scanEntropy
                true,   // scanKeys
                true,   // scanSignatures
                true,   // scanHardware
                true,   // scanNonCryptoEncodings
                7.2,    // entropyThreshold (Shannon bits/byte)
                16,     // minKeyLength (128-bit)
                32      // maxKeyLength (256-bit)
        );
    }
}
