package io.github.rezabakhshi.embedra.core.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.esp.EspAppDescriptionExtractor;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import java.io.IOException;
import java.io.InputStream;
import java.util.EnumMap;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/**
 * T071 Fuzz Campaign: At least 10,000 deterministic malformed inputs on ESP32 application format.
 */
public class Esp32BinaryFormatFuzzTest {

    public static final long SEED = 0x0E53_2032_0001L;

    public static final int CAMPAIGN_CASES = 10_000;

    @Test
    void runTenThousandDeterministicMalformedEsp32Inputs() throws Exception {
        byte[] golden = loadGoldenFixture();
        assertNotNull(golden, "Golden fixture must be present");

        DeterministicMutationEngine.CampaignResult result = runCampaign(golden, SEED, CAMPAIGN_CASES);

        assertEquals(CAMPAIGN_CASES, result.totalCases());
        assertEquals(CAMPAIGN_CASES, result.acceptedCount() + result.rejectedCount());
        assertTrue(result.acceptedCount() > 0, "Must accept golden baseline mutations");
        assertTrue(result.rejectedCount() > 0, "Must reject malformed mutations");

        // Repeat run with identical seed to prove 100% deterministic reproducibility
        DeterministicMutationEngine.CampaignResult repeatResult = runCampaign(golden, SEED, CAMPAIGN_CASES);
        assertEquals(result.outcomeSha256(), repeatResult.outcomeSha256(),
                "Outcome digest must be bit-for-bit identical");

        // Verify diagnostic coverage: every rejected input reported a valid typed diagnostic code
        int diagnosticSum = result.diagnosticCounts().values().stream().mapToInt(Integer::intValue).sum();
        assertEquals(result.rejectedCount(), diagnosticSum,
                "Every rejected input must have an associated diagnostic code");
        assertTrue(result.diagnosticCounts().keySet().stream()
                .allMatch(code -> code.id().startsWith("ESP_") || code.id().startsWith("CORE_")),
                "All diagnostics must be valid ESP or CORE codes");
    }

    public static DeterministicMutationEngine.CampaignResult runCampaign(byte[] golden, long seed, int count) {
        SplittableRandom random = new SplittableRandom(seed);
        StringBuilder outcomes = new StringBuilder(count * 32);
        EnumMap<DiagnosticCode, Integer> diagnostics = new EnumMap<>(DiagnosticCode.class);
        int accepted = 0;
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < count; i++) {
            final int caseIndex = i;
            byte[] mutation = DeterministicMutationEngine.mutate(golden, random, i);
            try {
                EspImage image = EspImageParser.parseForChip(
                        mutation, 9, ParserLimits.defaults(), CancellationToken.none());
                EspAppDescriptionExtractor.extract(image);
                accepted++;
                outcomes.append(i).append(":ACCEPT\n");
            } catch (DiagnosticException ex) {
                Diagnostic diagnostic = ex.diagnostic();
                diagnostic.sourceRange().ifPresent(range -> {
                    if (range.endExclusive() > mutation.length) {
                        throw new AssertionError("Diagnostic source range exceeds input at case " + caseIndex);
                    }
                });
                diagnostics.merge(diagnostic.code(), 1, Integer::sum);
                outcomes.append(i).append(':').append(diagnostic.code().id());
                diagnostic.sourceRange().ifPresent(range ->
                        outcomes.append('@').append(range.offset()).append('+').append(range.length()));
                outcomes.append('\n');
            } catch (Throwable t) {
                throw new AssertionError("Crash on ESP32 mutation case " + i + " (length " + mutation.length + "): "
                        + t.getClass().getName() + " - " + t.getMessage(), t);
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        String outcomeHash = DeterministicMutationEngine.computeSha256(outcomes.toString());
        return new DeterministicMutationEngine.CampaignResult(
                count, accepted, count - accepted, outcomeHash, diagnostics, elapsed);
    }

    private static byte[] loadGoldenFixture() throws IOException {
        try (InputStream stream = Esp32BinaryFormatFuzzTest.class.getResourceAsStream(
                "/fixtures/esp32s3/esp32s3-freestanding-minimal.bin")) {
            if (stream == null) {
                throw new IllegalStateException(
                        "Missing golden fixture /fixtures/esp32s3/esp32s3-freestanding-minimal.bin");
            }
            return stream.readAllBytes();
        }
    }
}
