package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.SplittableRandom;

/** Seeded bounded mutation campaign retained as deterministic T017 evidence. */
final class EspImageFuzzCampaign {
    private EspImageFuzzCampaign() {
    }

    static Result run(byte[] golden, long seed, int caseCount) {
        Objects.requireNonNull(golden, "golden");
        if (golden.length == 0 || caseCount <= 0) {
            throw new IllegalArgumentException("Fuzz campaign requires input and cases");
        }
        SplittableRandom random = new SplittableRandom(seed);
        StringBuilder outcomes = new StringBuilder();
        EnumMap<DiagnosticCode, Integer> diagnostics = new EnumMap<>(DiagnosticCode.class);
        int accepted = 0;
        for (int index = 0; index < caseCount; index++) {
            byte[] mutation = mutate(golden, random, index);
            try {
                EspImage image = EspImageParser.parseForChip(mutation, 9,
                    ParserLimits.defaults(), CancellationToken.none());
                EspAppDescriptionExtractor.extract(image);
                accepted++;
                outcomes.append(index).append(":ACCEPT\n");
            }
            catch (DiagnosticException failure) {
                Diagnostic diagnostic = failure.diagnostic();
                diagnostic.sourceRange().ifPresent(range -> {
                    if (range.endExclusive() > mutation.length) {
                        throw new AssertionError("Diagnostic exceeds fuzz input");
                    }
                });
                diagnostics.merge(diagnostic.code(), 1, Integer::sum);
                outcomes.append(index).append(':').append(diagnostic.code().id());
                diagnostic.sourceRange().ifPresent(range -> outcomes.append('@')
                    .append(range.offset()).append('+').append(range.length()));
                outcomes.append('\n');
            }
        }
        return new Result(caseCount, accepted, caseCount - accepted,
            sha256(outcomes.toString().getBytes(StandardCharsets.UTF_8)), diagnostics);
    }

    private static byte[] mutate(byte[] golden, SplittableRandom random, int index) {
        if (index % 16 == 0) {
            return golden.clone();
        }
        return switch (random.nextInt(4)) {
            case 0 -> Arrays.copyOf(golden, random.nextInt(golden.length + 1));
            case 1 -> flipBytes(golden, random);
            case 2 -> randomBytes(golden.length, random);
            default -> appendBytes(golden, random);
        };
    }

    private static byte[] flipBytes(byte[] golden, SplittableRandom random) {
        byte[] mutation = golden.clone();
        int flips = random.nextInt(1, 9);
        for (int index = 0; index < flips; index++) {
            int offset = random.nextInt(mutation.length);
            mutation[offset] ^= (byte) random.nextInt(1, 256);
        }
        return mutation;
    }

    private static byte[] randomBytes(int goldenLength, SplittableRandom random) {
        byte[] mutation = new byte[random.nextInt(goldenLength + 65)];
        random.nextBytes(mutation);
        if (mutation.length > 0 && random.nextBoolean()) {
            mutation[0] = (byte) EspImageDetector.MAGIC;
        }
        return mutation;
    }

    private static byte[] appendBytes(byte[] golden, SplittableRandom random) {
        byte[] mutation = Arrays.copyOf(golden, golden.length + random.nextInt(1, 33));
        byte[] suffix = new byte[mutation.length - golden.length];
        random.nextBytes(suffix);
        System.arraycopy(suffix, 0, mutation, golden.length, suffix.length);
        return mutation;
    }

    private static String sha256(byte[] input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Required SHA-256 implementation unavailable",
                exception);
        }
    }

    record Result(
            int caseCount,
            int acceptedCount,
            int rejectedCount,
            String outcomeSha256,
            Map<DiagnosticCode, Integer> diagnosticCounts) {
        Result {
            diagnosticCounts = Map.copyOf(diagnosticCounts);
        }
    }
}
