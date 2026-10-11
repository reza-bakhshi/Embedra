package io.github.rezabakhshi.embedra.core.fuzz;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.SplittableRandom;

/**
 * High-performance deterministic mutation engine for embedded binary parser fuzzing.
 */
public final class DeterministicMutationEngine {

    private static final long[] BOUNDARY_VALUES = {
        0L,
        1L,
        0xFFL,
        0xFFFFL,
        0x7FFF_FFFFL,
        0x8000_0000L,
        0xFFFF_FFFFL,
        0xDEAD_BEEFL,
        0xCAFE_BABEL
    };

    private DeterministicMutationEngine() {
    }

    /**
     * Outcome record for a completed deterministic malformed fuzz campaign.
     *
     * @param totalCases total number of inputs tested
     * @param acceptedCount inputs accepted as valid or partially valid
     * @param rejectedCount inputs safely rejected with typed diagnostics
     * @param outcomeSha256 SHA-256 digest of ordered execution outcomes
     * @param diagnosticCounts distribution of diagnostic codes observed
     * @param elapsedMillis execution time in milliseconds
     */
    public record CampaignResult(
            int totalCases,
            int acceptedCount,
            int rejectedCount,
            String outcomeSha256,
            Map<DiagnosticCode, Integer> diagnosticCounts,
            long elapsedMillis) {

        public CampaignResult {
            Objects.requireNonNull(outcomeSha256, "outcomeSha256");
            Objects.requireNonNull(diagnosticCounts, "diagnosticCounts");
            diagnosticCounts = Map.copyOf(diagnosticCounts);
        }
    }

    /**
     * Mutates a golden binary input deterministically using a seeded PRNG.
     *
     * @param golden golden or baseline valid input
     * @param random seeded PRNG
     * @param index iteration index
     * @return mutated byte array
     */
    public static byte[] mutate(byte[] golden, SplittableRandom random, int index) {
        Objects.requireNonNull(golden, "golden");
        if (index % 500 == 0) {
            return golden.clone();
        }
        if (index % 500 == 1) {
            return new byte[0];
        }
        if (index % 500 == 2) {
            return new byte[] {0};
        }
        if (index % 500 == 3) {
            return new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        }

        int strategy = random.nextInt(8);
        return switch (strategy) {
            case 0 -> truncate(golden, random);
            case 1 -> flipBytes(golden, random);
            case 2 -> randomBytes(golden.length, random);
            case 3 -> appendGarbage(golden, random);
            case 4 -> injectBoundaryValues(golden, random);
            case 5 -> zeroRange(golden, random);
            case 6 -> duplicateChunk(golden, random);
            default -> invertBits(golden, random);
        };
    }

    private static byte[] truncate(byte[] golden, SplittableRandom random) {
        if (golden.length == 0) {
            return new byte[0];
        }
        int newLength = random.nextInt(golden.length);
        return Arrays.copyOf(golden, newLength);
    }

    private static byte[] flipBytes(byte[] golden, SplittableRandom random) {
        if (golden.length == 0) {
            return new byte[] {(byte) random.nextInt(256)};
        }
        byte[] mutated = golden.clone();
        int flips = 1 + random.nextInt(Math.min(8, golden.length));
        for (int i = 0; i < flips; i++) {
            int offset = random.nextInt(mutated.length);
            mutated[offset] ^= (byte) (1 + random.nextInt(255));
        }
        return mutated;
    }

    private static byte[] randomBytes(int baseLength, SplittableRandom random) {
        int targetLen = random.nextInt(Math.min(baseLength * 2 + 64, 4096));
        byte[] bytes = new byte[targetLen];
        random.nextBytes(bytes);
        return bytes;
    }

    private static byte[] appendGarbage(byte[] golden, SplittableRandom random) {
        int appendLen = 1 + random.nextInt(64);
        byte[] mutated = Arrays.copyOf(golden, golden.length + appendLen);
        byte[] suffix = new byte[appendLen];
        random.nextBytes(suffix);
        System.arraycopy(suffix, 0, mutated, golden.length, appendLen);
        return mutated;
    }

    private static byte[] injectBoundaryValues(byte[] golden, SplittableRandom random) {
        if (golden.length < 4) {
            return flipBytes(golden, random);
        }
        byte[] mutated = golden.clone();
        int offset = random.nextInt(mutated.length - 3);
        long val = BOUNDARY_VALUES[random.nextInt(BOUNDARY_VALUES.length)];
        mutated[offset] = (byte) (val & 0xff);
        mutated[offset + 1] = (byte) ((val >>> 8) & 0xff);
        mutated[offset + 2] = (byte) ((val >>> 16) & 0xff);
        mutated[offset + 3] = (byte) ((val >>> 24) & 0xff);
        return mutated;
    }

    private static byte[] zeroRange(byte[] golden, SplittableRandom random) {
        if (golden.length < 4) {
            return new byte[golden.length];
        }
        byte[] mutated = golden.clone();
        int offset = random.nextInt(mutated.length - 3);
        int length = Math.min(mutated.length - offset, 4 + random.nextInt(28));
        Arrays.fill(mutated, offset, offset + length, (byte) 0);
        return mutated;
    }

    private static byte[] duplicateChunk(byte[] golden, SplittableRandom random) {
        if (golden.length < 8) {
            return flipBytes(golden, random);
        }
        byte[] mutated = golden.clone();
        int srcOffset = random.nextInt(mutated.length - 4);
        int chunkLen = Math.min(mutated.length - srcOffset, 4 + random.nextInt(12));
        int dstOffset = random.nextInt(mutated.length - chunkLen);
        System.arraycopy(mutated, srcOffset, mutated, dstOffset, chunkLen);
        return mutated;
    }

    private static byte[] invertBits(byte[] golden, SplittableRandom random) {
        if (golden.length == 0) {
            return new byte[0];
        }
        byte[] mutated = golden.clone();
        int offset = random.nextInt(mutated.length);
        int count = Math.min(mutated.length - offset, 1 + random.nextInt(8));
        for (int i = 0; i < count; i++) {
            mutated[offset + i] = (byte) (~mutated[offset + i]);
        }
        return mutated;
    }

    /**
     * Computes the SHA-256 digest of UTF-8 string data.
     *
     * @param text input text
     * @return 64-character lowercase hexadecimal hash
     */
    public static String computeSha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
