package io.github.rezabakhshi.embedra.core.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266Image;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266ImageParser;
import java.io.IOException;
import java.io.InputStream;
import java.util.EnumMap;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/**
 * T071 Fuzz Campaign: At least 10,000 deterministic malformed inputs on ESP8266 format (v1 and v2).
 */
public class Esp8266BinaryFormatFuzzTest {

    public static final long SEED = 0x8266_F022_0002L;

    public static final int CAMPAIGN_CASES = 10_000;

    @Test
    void runTenThousandDeterministicMalformedEsp8266Inputs() throws Exception {
        byte[] goldenV1 = loadFixture("/fixtures/esp8266/esp8266-freestanding-v1-0x00000.bin");
        byte[] goldenV2 = loadFixture("/fixtures/esp8266/esp8266-freestanding-v2-0x01000.bin");
        assertNotNull(goldenV1, "Golden v1 fixture must be present");
        assertNotNull(goldenV2, "Golden v2 fixture must be present");

        DeterministicMutationEngine.CampaignResult result = runCampaign(goldenV1, goldenV2, SEED, CAMPAIGN_CASES);

        assertEquals(CAMPAIGN_CASES, result.totalCases());
        assertEquals(CAMPAIGN_CASES, result.acceptedCount() + result.rejectedCount());
        assertTrue(result.acceptedCount() > 0, "Must accept golden baseline mutations");
        assertTrue(result.rejectedCount() > 0, "Must reject malformed mutations");

        // Repeat run with identical seed to prove 100% deterministic reproducibility
        DeterministicMutationEngine.CampaignResult repeatResult =
                runCampaign(goldenV1, goldenV2, SEED, CAMPAIGN_CASES);
        assertEquals(result.outcomeSha256(), repeatResult.outcomeSha256(),
                "Outcome digest must be bit-for-bit identical");

        // Verify diagnostic coverage
        int diagnosticSum = result.diagnosticCounts().values().stream().mapToInt(Integer::intValue).sum();
        assertEquals(result.rejectedCount(), diagnosticSum,
                "Every rejected input must have an associated diagnostic code");
        assertTrue(result.diagnosticCounts().keySet().stream()
                .allMatch(code -> code.id().startsWith("ESP8266_") || code.id().startsWith("CORE_")
                        || code.id().equals("LIMIT_EXCEEDED")),
                "All diagnostics must be valid ESP8266 or CORE codes");
    }

    public static DeterministicMutationEngine.CampaignResult runCampaign(
            byte[] goldenV1, byte[] goldenV2, long seed, int count) {
        SplittableRandom random = new SplittableRandom(seed);
        StringBuilder outcomes = new StringBuilder(count * 32);
        EnumMap<DiagnosticCode, Integer> diagnostics = new EnumMap<>(DiagnosticCode.class);
        int accepted = 0;
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < count; i++) {
            final int caseIndex = i;
            byte[] baseline = (i % 2 == 0) ? goldenV1 : goldenV2;
            byte[] mutation = DeterministicMutationEngine.mutate(baseline, random, i);
            try {
                Esp8266Image image = Esp8266ImageParser.parse(
                        mutation, ParserLimits.defaults(), CancellationToken.none());
                assertNotNull(image);
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
                throw new AssertionError("Crash on ESP8266 mutation case " + i + " (length " + mutation.length + "): "
                        + t.getClass().getName() + " - " + t.getMessage(), t);
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        String outcomeHash = DeterministicMutationEngine.computeSha256(outcomes.toString());
        return new DeterministicMutationEngine.CampaignResult(
                count, accepted, count - accepted, outcomeHash, diagnostics, elapsed);
    }

    private static byte[] loadFixture(String path) throws IOException {
        try (InputStream stream = Esp8266BinaryFormatFuzzTest.class.getResourceAsStream(path)) {
            if (stream == null) {
                throw new IllegalStateException("Missing fixture " + path);
            }
            return stream.readAllBytes();
        }
    }
}
