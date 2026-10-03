package io.github.rezabakhshi.embedra.analyzers.strings;

/**
 * Configurable options controlling multi-encoding string extraction thresholds and heuristics.
 */
public record StringScanOptions(
        int minLength,
        double minPrintableRatio,
        boolean scanAscii,
        boolean scanUtf8,
        boolean scanUtf16Le,
        boolean scanUtf16Be,
        boolean scanPascal,
        int maxStrings) {

    public StringScanOptions {
        if (minLength <= 0) {
            throw new IllegalArgumentException("Minimum string length must be positive");
        }
        if (minPrintableRatio <= 0.0 || minPrintableRatio > 1.0) {
            throw new IllegalArgumentException("Minimum printable ratio must be in (0.0, 1.0]");
        }
        if (maxStrings <= 0) {
            throw new IllegalArgumentException("Max strings must be positive");
        }
    }

    public static StringScanOptions defaults() {
        return new StringScanOptions(4, 0.85, true, true, true, true, true, 100_000);
    }
}
