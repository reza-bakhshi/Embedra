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
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Scanner for bounded candidate cryptographic key material (128-bit, 192-bit, 256-bit)
 * with strict false-positive controls (AN-003, AN-008, AN-010).
 */
public final class LikelyKeyScanner {

    private static final int[] KEY_SIZES = { 16, 24, 32 };

    private static final int WORD_ALIGNMENT = 4;

    public List<CryptoFinding> scan(
            byte[] data,
            long baseAddress,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        int scanLength = (int) Math.min(data.length, limits.maxInputBytes());
        List<CryptoFinding> findings = new ArrayList<>();
        HexFormat hex = HexFormat.of();

        // Scan candidate key lengths at word-aligned boundaries
        for (int keySize : KEY_SIZES) {
            CryptoAlgorithm algo = switch (keySize) {
                case 16 -> CryptoAlgorithm.AES_128;
                case 24 -> CryptoAlgorithm.AES_192;
                case 32 -> CryptoAlgorithm.AES_256;
                default -> CryptoAlgorithm.GENERIC_KEY;
            };

            for (int offset = 0; offset + keySize <= scanLength; offset += WORD_ALIGNMENT) {
                if ((offset & 0x3FFF) == 0) {
                    token.throwIfCancellationRequested();
                }

                if (isLikelyKeyMaterial(data, offset, keySize)) {
                    long addr = baseAddress + offset;
                    byte[] keyBytes = new byte[keySize];
                    System.arraycopy(data, offset, keyBytes, 0, keySize);
                    String hexValue = hex.formatHex(keyBytes);

                    double entropy = calculateEntropy(data, offset, keySize);
                    int distinct = countDistinctBytes(data, offset, keySize);

                    String explanation = String.format(
                            Locale.ROOT,
                            "Candidate %d-bit symmetric key material (Shannon: %.2f bits/byte, %d distinct bytes)",
                            keySize * 8, entropy, distinct);

                    findings.add(new CryptoFinding(
                            "KEY_" + (keySize * 8) + "_" + Long.toHexString(addr),
                            addr,
                            keySize,
                            CryptoCategory.KEY_MATERIAL,
                            algo,
                            CryptoConfidence.PLAUSIBLE,
                            Set.of(CryptoEvidenceLayer.ENTROPY_METRIC),
                            explanation,
                            hexValue,
                            true // Secret key material (AN-008)
                    ));

                    // Skip past this key to avoid overlapping findings for the same candidate
                    offset += keySize - WORD_ALIGNMENT;

                    if (findings.size() >= limits.maxObjects()) {
                        return List.copyOf(findings);
                    }
                }
            }
        }

        return List.copyOf(findings);
    }

    /**
     * Strict false-positive filter evaluating randomness, repetition, code idioms, and text heuristics.
     */
    public static boolean isLikelyKeyMaterial(byte[] data, int offset, int keySize) {
        if (offset < 0 || offset + keySize > data.length) {
            return false;
        }

        // 1. Zero runs: reject if more than 1 zero byte or any consecutive zeros
        int zeroCount = 0;
        for (int i = 0; i < keySize; i++) {
            if (data[offset + i] == 0) {
                zeroCount++;
                if (zeroCount > 1) {
                    return false;
                }
                if (i > 0 && data[offset + i - 1] == 0) {
                    return false;
                }
            }
        }

        // 2. Distinct byte count threshold
        int minDistinct = switch (keySize) {
            case 16 -> 13;
            case 24 -> 19;
            case 32 -> 25;
            default -> (int) (keySize * 0.75);
        };
        int distinct = countDistinctBytes(data, offset, keySize);
        if (distinct < minDistinct) {
            return false;
        }

        // 3. Reject repetitive patterns (2-byte or 4-byte repeats)
        if (isRepetitivePattern(data, offset, keySize)) {
            return false;
        }

        // 4. Reject ASCII text strings (if >= 75% printable ASCII)
        int asciiCount = 0;
        for (int i = 0; i < keySize; i++) {
            int b = data[offset + i] & 0xFF;
            if (b >= 0x20 && b <= 0x7E) {
                asciiCount++;
            }
        }
        if (asciiCount >= (keySize * 3) / 4) {
            return false;
        }

        // 5. Code unit patterns filter (ARM / RISC-V / Xtensa)
        if (matchesCodePattern(data, offset, keySize)) {
            return false;
        }

        // 6. Shannon entropy threshold
        double minEntropy = switch (keySize) {
            case 16 -> 3.6;
            case 24 -> 4.0;
            case 32 -> 4.4;
            default -> 3.5;
        };
        double entropy = calculateEntropy(data, offset, keySize);
        return entropy >= minEntropy;
    }

    private static int countDistinctBytes(byte[] data, int offset, int length) {
        boolean[] seen = new boolean[256];
        int count = 0;
        for (int i = 0; i < length; i++) {
            int b = data[offset + i] & 0xFF;
            if (!seen[b]) {
                seen[b] = true;
                count++;
            }
        }
        return count;
    }

    private static boolean isRepetitivePattern(byte[] data, int offset, int length) {
        // Check 2-byte repetition (e.g. 0x55 0xAA 0x55 0xAA...)
        boolean twoByteRepeat = true;
        for (int i = 2; i < length; i++) {
            if (data[offset + i] != data[offset + (i % 2)]) {
                twoByteRepeat = false;
                break;
            }
        }
        if (twoByteRepeat) {
            return true;
        }

        // Check 4-byte repetition
        if (length >= 8) {
            boolean fourByteRepeat = true;
            for (int i = 4; i < length; i++) {
                if (data[offset + i] != data[offset + (i % 4)]) {
                    fourByteRepeat = false;
                    break;
                }
            }
            if (fourByteRepeat) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchesCodePattern(byte[] data, int offset, int length) {
        // Check for common ARM Thumb instruction sequences
        for (int i = 0; i + 1 < length; i += 2) {
            int h16 = ((data[offset + i + 1] & 0xFF) << 8) | (data[offset + i] & 0xFF);
            // Thumb NOP: 0xBF00
            if (h16 == 0xBF00) {
                return true;
            }
            // Thumb push {..., lr}: 0xB5XX
            if ((h16 & 0xFF00) == 0xB500) {
                return true;
            }
            // Thumb pop {..., pc}: 0xBDXX
            if ((h16 & 0xFF00) == 0xBD00) {
                return true;
            }
        }

        // Check for ARM32 NOP: 0xE1A00000
        for (int i = 0; i + 3 < length; i += 4) {
            int w = ((data[offset + i + 3] & 0xFF) << 24)
                    | ((data[offset + i + 2] & 0xFF) << 16)
                    | ((data[offset + i + 1] & 0xFF) << 8)
                    | (data[offset + i] & 0xFF);
            if (w == 0xE1A00000) {
                return true;
            }
        }

        // Check for RISC-V NOP: 0x00000013 or c.nop 0x0001
        for (int i = 0; i + 1 < length; i += 2) {
            int h16 = ((data[offset + i + 1] & 0xFF) << 8) | (data[offset + i] & 0xFF);
            if (h16 == 0x0001) {
                return true;
            }
        }

        return false;
    }

    private static double calculateEntropy(byte[] data, int offset, int length) {
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
        return entropy;
    }
}
