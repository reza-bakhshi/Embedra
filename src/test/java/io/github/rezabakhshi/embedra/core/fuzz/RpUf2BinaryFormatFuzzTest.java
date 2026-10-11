package io.github.rezabakhshi.embedra.core.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Image;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Parser;
import java.io.IOException;
import java.io.InputStream;
import java.util.EnumMap;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/**
 * T071 Fuzz Campaign: At least 10,000 deterministic malformed inputs on Raspberry Pi UF2 format.
 */
public class RpUf2BinaryFormatFuzzTest {

    public static final long SEED = 0x2040_2350_0003L;

    public static final int CAMPAIGN_CASES = 10_000;

    @Test
    void runTenThousandDeterministicMalformedRpUf2Inputs() throws Exception {
        byte[] golden = loadFixture("/fixtures/rp/rp2040-pico-blinky.uf2");
        assertNotNull(golden, "Golden UF2 fixture must be present");

        DeterministicMutationEngine.CampaignResult result = runCampaign(golden, SEED, CAMPAIGN_CASES);

        assertEquals(CAMPAIGN_CASES, result.totalCases());
        assertEquals(CAMPAIGN_CASES, result.acceptedCount() + result.rejectedCount());
        assertTrue(result.acceptedCount() > 0, "Must accept golden baseline mutations");
        assertTrue(result.rejectedCount() > 0, "Must reject malformed mutations");

        // Repeat run with identical seed to prove 100% deterministic reproducibility
        DeterministicMutationEngine.CampaignResult repeatResult = runCampaign(golden, SEED, CAMPAIGN_CASES);
        assertEquals(result.outcomeSha256(), repeatResult.outcomeSha256(),
                "Outcome digest must be bit-for-bit identical");

        // Verify diagnostic coverage
        int diagnosticSum = result.diagnosticCounts().values().stream().mapToInt(Integer::intValue).sum();
        assertEquals(result.rejectedCount(), diagnosticSum,
                "Every rejected input must have an associated diagnostic code");
        assertTrue(result.diagnosticCounts().keySet().stream()
                .allMatch(code -> code.id().startsWith("RP_") || code.id().startsWith("CORE_")),
                "All diagnostics must be valid RP or CORE codes");
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
                RpUf2Image uf2 = RpUf2Parser.parse(mutation, ParserLimits.defaults(), CancellationToken.none());
                assertNotNull(uf2);
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
                throw new AssertionError("Crash on RP UF2 mutation case " + i + " (length " + mutation.length + "): "
                        + t.getClass().getName() + " - " + t.getMessage(), t);
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        String outcomeHash = DeterministicMutationEngine.computeSha256(outcomes.toString());
        return new DeterministicMutationEngine.CampaignResult(
                count, accepted, count - accepted, outcomeHash, diagnostics, elapsed);
    }

    private static byte[] loadFixture(String path) throws IOException {
        try (InputStream stream = RpUf2BinaryFormatFuzzTest.class.getResourceAsStream(path)) {
            if (stream == null) {
                throw new IllegalStateException("Missing fixture " + path);
            }
            return stream.readAllBytes();
        }
    }
}
