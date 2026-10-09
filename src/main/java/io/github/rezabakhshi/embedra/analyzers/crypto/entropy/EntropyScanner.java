package io.github.rezabakhshi.embedra.analyzers.crypto.entropy;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Sliding-window Shannon entropy scanner with statistical chi-squared and distribution metrics (AN-003, AN-010).
 *
 * <p>Identifies high-entropy payloads (>= 7.2 bits/byte) while strictly ensuring entropy anomalies alone
 * are never classified as encryption (AN-003).</p>
 */
public final class EntropyScanner {

    public static final int DEFAULT_WINDOW_SIZE = 512;

    public static final int DEFAULT_STEP_SIZE = 128;

    public static final double DEFAULT_THRESHOLD = 7.2;

    private final int windowSize;

    private final int stepSize;

    public EntropyScanner() {
        this(DEFAULT_WINDOW_SIZE, DEFAULT_STEP_SIZE);
    }

    public EntropyScanner(int windowSize, int stepSize) {
        if (windowSize <= 0) {
            throw new IllegalArgumentException("windowSize must be positive: " + windowSize);
        }
        if (stepSize <= 0 || stepSize > windowSize) {
            throw new IllegalArgumentException("stepSize must be in (0, windowSize]: " + stepSize);
        }
        this.windowSize = windowSize;
        this.stepSize = stepSize;
    }

    /**
     * Calculates Shannon entropy and chi-squared metric for a single byte slice.
     */
    public static EntropyResult calculate(byte[] data, int offset, int length) {
        Objects.requireNonNull(data, "data must not be null");
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IndexOutOfBoundsException("Invalid slice bounds");
        }
        if (length == 0) {
            return new EntropyResult(0.0, 0.0, false, false, false);
        }

        int[] counts = new int[256];
        for (int i = 0; i < length; i++) {
            counts[data[offset + i] & 0xFF]++;
        }

        double entropy = 0.0;
        double log2 = Math.log(2.0);
        double len = length;

        for (int count : counts) {
            if (count > 0) {
                double p = count / len;
                entropy -= p * (Math.log(p) / log2);
            }
        }

        // Chi-squared test against uniform distribution: E = length / 256
        double expected = len / 256.0;
        double chiSquared = 0.0;
        for (int count : counts) {
            double diff = count - expected;
            chiSquared += (diff * diff) / expected;
        }

        boolean highEntropy = entropy >= DEFAULT_THRESHOLD;
        boolean hasCompressionHeader = isCompressionHeader(data, offset, length);
        // Compressed streams typically exhibit higher chi-squared skew (> 350 for 256 bytes) or compression headers
        boolean likelyCompressed = hasCompressionHeader || (highEntropy && chiSquared > 360.0);
        boolean likelyCiphertext = highEntropy && !likelyCompressed;

        return new EntropyResult(entropy, chiSquared, highEntropy, likelyCompressed, likelyCiphertext);
    }

    /**
     * Scans the buffer using a sliding window and merges consecutive high-entropy blocks into findings.
     */
    public List<CryptoFinding> scan(
            byte[] data,
            long baseAddress,
            double threshold,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        int scanLength = (int) Math.min(data.length, limits.maxInputBytes());
        if (scanLength < windowSize) {
            if (scanLength >= 64) {
                EntropyResult r = calculate(data, 0, scanLength);
                if (r.entropy() >= threshold) {
                    return List.of(createFinding(baseAddress, scanLength, r));
                }
            }
            return List.of();
        }

        List<Range> highEntropyRanges = new ArrayList<>();
        int currentStart = -1;
        int currentEnd = -1;
        double maxEntropy = 0.0;
        double sumChiSquared = 0.0;
        int windowCount = 0;
        boolean sawCompression = false;

        for (int offset = 0; offset + windowSize <= scanLength; offset += stepSize) {
            if ((offset & 0x3FFF) == 0) {
                token.throwIfCancellationRequested();
            }

            EntropyResult res = calculate(data, offset, windowSize);
            if (res.entropy() >= threshold) {
                if (currentStart == -1) {
                    currentStart = offset;
                    currentEnd = offset + windowSize;
                    maxEntropy = res.entropy();
                    sumChiSquared = res.chiSquared();
                    windowCount = 1;
                    sawCompression = res.likelyCompressed();
                } else {
                    currentEnd = offset + windowSize;
                    maxEntropy = Math.max(maxEntropy, res.entropy());
                    sumChiSquared += res.chiSquared();
                    windowCount++;
                    if (res.likelyCompressed()) {
                        sawCompression = true;
                    }
                }
            } else {
                if (currentStart != -1) {
                    highEntropyRanges.add(new Range(
                            currentStart, currentEnd, maxEntropy,
                            sumChiSquared / windowCount, sawCompression));
                    currentStart = -1;
                    currentEnd = -1;
                }
            }
        }

        if (currentStart != -1) {
            highEntropyRanges.add(new Range(
                    currentStart, currentEnd, maxEntropy,
                    sumChiSquared / windowCount, sawCompression));
        }

        List<CryptoFinding> findings = new ArrayList<>();
        for (Range r : highEntropyRanges) {
            long addr = baseAddress + r.start;
            int length = r.end - r.start;
            String typeDesc = r.compressed ? "compressed stream" : "dense ciphertext / key block";
            String explanation = String.format(
                    Locale.ROOT,
                    "High-entropy region (%.2f bits/byte, chi-sq: %.1f, length: %d bytes) - likely %s",
                    r.entropy, r.chiSquared, length, typeDesc);

            String rawSummary = String.format(
                    Locale.ROOT,
                    "[Entropy: %.2f bits/byte, length: %d]",
                    r.entropy, length);

            findings.add(new CryptoFinding(
                    "ENTROPY_" + Long.toHexString(addr),
                    addr,
                    length,
                    CryptoCategory.ENTROPY_ANOMALY,
                    CryptoAlgorithm.HIGH_ENTROPY_BLOCK,
                    CryptoConfidence.PLAUSIBLE,
                    CryptoEvidenceLayer.ENTROPY_METRIC,
                    explanation,
                    rawSummary,
                    false // Not a secret key by itself
            ));

            if (findings.size() >= limits.maxObjects()) {
                break;
            }
        }

        return List.copyOf(findings);
    }

    private static CryptoFinding createFinding(long address, int length, EntropyResult r) {
        String typeDesc = r.likelyCompressed() ? "compressed stream" : "dense ciphertext / key block";
        String explanation = String.format(
                Locale.ROOT,
                "High-entropy region (%.2f bits/byte, chi-sq: %.1f, length: %d bytes) - likely %s",
                r.entropy(), r.chiSquared(), length, typeDesc);
        String rawSummary = String.format(
                Locale.ROOT,
                "[Entropy: %.2f bits/byte, length: %d]",
                r.entropy(), length);

        return new CryptoFinding(
                "ENTROPY_" + Long.toHexString(address),
                address,
                length,
                CryptoCategory.ENTROPY_ANOMALY,
                CryptoAlgorithm.HIGH_ENTROPY_BLOCK,
                CryptoConfidence.PLAUSIBLE,
                CryptoEvidenceLayer.ENTROPY_METRIC,
                explanation,
                rawSummary,
                false
        );
    }

    private static boolean isCompressionHeader(byte[] data, int offset, int length) {
        if (length < 2) {
            return false;
        }
        int b0 = data[offset] & 0xFF;
        int b1 = data[offset + 1] & 0xFF;

        // zlib header (0x78 0x01, 0x78 0x9C, 0x78 0xDA)
        if (b0 == 0x78 && (b1 == 0x01 || b1 == 0x9C || b1 == 0xDA || ((b0 * 256 + b1) % 31 == 0))) {
            return true;
        }
        // gzip header (0x1F 0x8B)
        if (b0 == 0x1F && b1 == 0x8B) {
            return true;
        }
        // bzip2 (0x42 0x5A)
        if (b0 == 0x42 && b1 == 0x5A) {
            return true;
        }
        // LZ4 (0x04 0x22 0x4D 0x18)
        if (length >= 4 && b0 == 0x04 && b1 == 0x22
                && (data[offset + 2] & 0xFF) == 0x4D && (data[offset + 3] & 0xFF) == 0x18) {
            return true;
        }
        // xz (0xFD 0x37 0x7A 0x58 0x5A 0x00)
        if (length >= 6 && b0 == 0xFD && b1 == 0x37 && (data[offset + 2] & 0xFF) == 0x7A) {
            return true;
        }
        return false;
    }

    private record Range(int start, int end, double entropy, double chiSquared, boolean compressed) {
    }
}
