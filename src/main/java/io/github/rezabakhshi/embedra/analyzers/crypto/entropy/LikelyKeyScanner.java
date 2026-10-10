package io.github.rezabakhshi.embedra.analyzers.crypto.entropy;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.crypto.tables.CryptoTableDatabase;
import io.github.rezabakhshi.embedra.analyzers.crypto.tables.CryptoTableSignature;
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

    private static final List<byte[]> KNOWN_TABLE_PATTERNS = buildKnownTablePatterns();

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

        // Scan candidate key lengths at word-aligned boundaries, prioritizing largest candidate keys
        boolean[] claimed = new boolean[scanLength];
        for (int offset = 0; offset + 16 <= scanLength; offset += WORD_ALIGNMENT) {
            if ((offset & 0x3FFF) == 0) {
                token.throwIfCancellationRequested();
            }

            if (claimed[offset]) {
                continue;
            }

            for (int keySize : new int[] {32, 24, 16}) {
                if (offset + keySize <= scanLength && isLikelyKeyMaterial(data, offset, keySize)) {
                    CryptoAlgorithm algo = switch (keySize) {
                        case 16 -> CryptoAlgorithm.AES_128;
                        case 24 -> CryptoAlgorithm.AES_192;
                        case 32 -> CryptoAlgorithm.AES_256;
                        default -> CryptoAlgorithm.GENERIC_KEY;
                    };

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

                    for (int c = offset; c < offset + keySize && c < scanLength; c++) {
                        claimed[c] = true;
                    }

                    if (findings.size() >= limits.maxObjects()) {
                        return List.copyOf(findings);
                    }
                    break;
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

        // 3. Dynamic range / value spread filter (reject narrow-range tables like frequency/weight matrices)
        int minByte = 255;
        int maxByte = 0;
        for (int i = 0; i < keySize; i++) {
            int b = data[offset + i] & 0xFF;
            if (b < minByte) {
                minByte = b;
            }
            if (b > maxByte) {
                maxByte = b;
            }
        }
        if (maxByte - minByte < 64) {
            return false;
        }

        // 4. Reject repetitive patterns (2-byte or 4-byte repeats) and arithmetic progressions
        if (isRepetitivePattern(data, offset, keySize) || isArithmeticSequence(data, offset, keySize)) {
            return false;
        }

        // 5. Reject ASCII text strings (if > 87.5% printable ASCII, e.g. text phrases and names)
        int asciiCount = 0;
        for (int i = 0; i < keySize; i++) {
            int b = data[offset + i] & 0xFF;
            if (b >= 0x20 && b <= 0x7E) {
                asciiCount++;
            }
        }
        if (asciiCount > (keySize * 7) / 8) {
            return false;
        }

        // 6. Code unit patterns filter (ARM Thumb/Thumb-2 / ARM32 / RISC-V / Xtensa)
        if (matchesCodePattern(data, offset, keySize)) {
            return false;
        }

        // 7. Constant table exclusion (AN-014: never label a fixed constant as a secret key)
        if (isKnownConstantTable(data, offset, keySize)) {
            return false;
        }

        // 8. Smooth curve mathematical filter (e.g. sine tables, sensor polynomials)
        if (isSmoothMathematicalCurve(data, offset, keySize)) {
            return false;
        }

        // 9. Continuous high-entropy region filter (AN-014: never label an entropy region as a key)
        if (isContinuousEntropyStream(data, offset, keySize)) {
            return false;
        }

        // 10. Shannon entropy threshold
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

    private static boolean isArithmeticSequence(byte[] data, int offset, int length) {
        if (length < 4) {
            return false;
        }
        int step = (data[offset + 1] - data[offset]) & 0xFF;
        for (int i = 1; i < length - 1; i++) {
            int diff = (data[offset + i + 1] - data[offset + i]) & 0xFF;
            if (diff != step) {
                return false;
            }
        }
        return true;
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
        // Check 16-bit instruction sequences (Thumb NOP, RISC-V compressed NOP)
        for (int i = 0; i + 1 < length; i += 2) {
            int b0 = data[offset + i] & 0xFF;
            int b1 = data[offset + i + 1] & 0xFF;
            int h16LE = (b1 << 8) | b0;
            int h16BE = (b0 << 8) | b1;

            // Thumb NOP: 0xBF00
            if (h16LE == 0xBF00 || h16BE == 0xBF00) {
                return true;
            }
            // RISC-V c.nop: 0x0001
            if (h16LE == 0x0001 || h16BE == 0x0001) {
                return true;
            }
        }

        // Check multi-instruction sequences (Thumb function prologues)
        for (int i = 0; i + 3 < length; i += 2) {
            int b0 = data[offset + i] & 0xFF;
            int b1 = data[offset + i + 1] & 0xFF;
            int b2 = data[offset + i + 2] & 0xFF;
            int b3 = data[offset + i + 3] & 0xFF;

            // Thumb PUSH {..., lr} followed by instruction (mov rX, rY or sub sp, #imm)
            boolean isPushLE = (b1 == 0xB5);
            boolean isPushBE = (b0 == 0xB5);
            if (isPushLE && (b3 == 0x46 || (b3 & 0xF0) == 0xB0 || b3 == 0x48)) {
                return true;
            }
            if (isPushBE && (b2 == 0x46 || (b2 & 0xF0) == 0xB0 || b2 == 0x48)) {
                return true;
            }

            int wLE = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
            int wBE = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

            // ARM32 NOP: 0xE1A00000
            if (wLE == 0xE1A00000 || wBE == 0xE1A00000) {
                return true;
            }
            // RISC-V NOP: 0x00000013
            if (wLE == 0x00000013 || wBE == 0x00000013) {
                return true;
            }
            // RISC-V addi sp, sp, -imm: (w & 0x000FFFFF) == 0x00010113 (LE)
            if ((wLE & 0x000FFFFF) == 0x00010113) {
                return true;
            }
            // Thumb-2 PUSH.W / STMDB sp!, {regs, lr}: 0xE92D with LR bit in halfword 2
            if ((b0 == 0x2D && b1 == 0xE9) || (b0 == 0xE9 && b1 == 0x2D)) {
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

    private static List<byte[]> buildKnownTablePatterns() {
        return new CryptoTableDatabase().signatures().stream()
                .map(CryptoTableSignature::pattern)
                .toList();
    }

    private static boolean isKnownConstantTable(byte[] data, int offset, int keySize) {
        for (byte[] table : KNOWN_TABLE_PATTERNS) {
            if (containsSubsequence(table, data, offset, keySize)) {
                return true;
            }
            // Candidate keys must not overlap 8 or more bytes of any known cryptographic table
            if (table.length >= 8) {
                for (int i = 0; i <= keySize - 8; i += 4) {
                    if (containsSubsequence(table, data, offset + i, 8)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean containsSubsequence(byte[] haystack, byte[] needle, int offset, int len) {
        if (len > haystack.length || offset + len > needle.length) {
            return false;
        }
        outer:
        for (int i = 0; i <= haystack.length - len; i++) {
            for (int j = 0; j < len; j++) {
                if (haystack[i + j] != needle[offset + j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static boolean isSmoothMathematicalCurve(byte[] data, int offset, int keySize) {
        int wordCount = keySize / 2;
        if (wordCount < 4) {
            return false;
        }
        int smallDeltas = 0;
        for (int i = 0; i < wordCount - 1; i++) {
            int w1 = (data[offset + i * 2] & 0xFF) | ((data[offset + i * 2 + 1] & 0xFF) << 8);
            int w2 = (data[offset + (i + 1) * 2] & 0xFF) | ((data[offset + (i + 1) * 2 + 1] & 0xFF) << 8);
            if (Math.abs(w2 - w1) < 2500) {
                smallDeltas++;
            }
        }
        return smallDeltas >= wordCount - 2;
    }

    private static boolean isContinuousEntropyStream(byte[] data, int offset, int keySize) {
        // AN-014: Never label an extended entropy region as a recovered secret key without corroboration
        if (data.length < 256) {
            return false;
        }
        int window = 256;
        int winStart = Math.max(0, Math.min(offset - 64, data.length - window));
        double winEntropy = calculateEntropy(data, winStart, window);
        return winEntropy >= 7.0;
    }
}
