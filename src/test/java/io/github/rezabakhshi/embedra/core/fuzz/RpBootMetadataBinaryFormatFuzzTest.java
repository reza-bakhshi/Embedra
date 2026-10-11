package io.github.rezabakhshi.embedra.core.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2040Boot2Checksum;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2040BootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350BootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadataParser;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.EnumMap;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/**
 * T071 Fuzz Campaign: At least 10,000 deterministic malformed inputs on RP boot metadata (Boot2 & ImageDef).
 */
public class RpBootMetadataBinaryFormatFuzzTest {

    public static final long SEED = 0xDEAD_BEEF_0007L;

    public static final int CAMPAIGN_CASES = 10_000;

    @Test
    void runTenThousandDeterministicMalformedRpBootMetadataInputs() {
        byte[] goldenBoot2 = createValidRp2040Boot2();
        byte[] goldenImageDef = createValidRp2350ImageDef();
        assertNotNull(goldenBoot2);
        assertNotNull(goldenImageDef);

        DeterministicMutationEngine.CampaignResult result =
                runCampaign(goldenBoot2, goldenImageDef, SEED, CAMPAIGN_CASES);

        assertEquals(CAMPAIGN_CASES, result.totalCases());
        assertEquals(CAMPAIGN_CASES, result.acceptedCount() + result.rejectedCount());
        assertTrue(result.acceptedCount() > 0, "Must accept golden baseline mutations");
        assertTrue(result.rejectedCount() > 0, "Must reject malformed mutations");

        // Repeat run with identical seed to prove 100% deterministic reproducibility
        DeterministicMutationEngine.CampaignResult repeatResult =
                runCampaign(goldenBoot2, goldenImageDef, SEED, CAMPAIGN_CASES);
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

    public static DeterministicMutationEngine.CampaignResult runCampaign(
            byte[] goldenBoot2, byte[] goldenImageDef, long seed, int count) {
        SplittableRandom random = new SplittableRandom(seed);
        StringBuilder outcomes = new StringBuilder(count * 32);
        EnumMap<DiagnosticCode, Integer> diagnostics = new EnumMap<>(DiagnosticCode.class);
        int accepted = 0;
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < count; i++) {
            final int caseIndex = i;
            if (i % 2 == 0) {
                // RP2040 Boot2 test
                byte[] mutation = DeterministicMutationEngine.mutate(goldenBoot2, random, i);
                try {
                    Rp2040BootMetadata meta = RpBootMetadataParser.parseRp2040Strict(mutation, 0x1000_0000L);
                    assertNotNull(meta);
                    accepted++;
                    outcomes.append(i).append(":ACCEPT:BOOT2\n");
                } catch (DiagnosticException ex) {
                    Diagnostic diagnostic = ex.diagnostic();
                    diagnostics.merge(diagnostic.code(), 1, Integer::sum);
                    outcomes.append(i).append(':').append(diagnostic.code().id());
                    diagnostic.sourceRange().ifPresent(range ->
                            outcomes.append('@').append(range.offset()).append('+').append(range.length()));
                    outcomes.append('\n');
                } catch (Throwable t) {
                    throw new AssertionError("Crash on Boot2 mutation case " + i + " (length " + mutation.length + "): "
                            + t.getClass().getName() + " - " + t.getMessage(), t);
                }
            } else {
                // RP2350 ImageDef test
                byte[] mutation = DeterministicMutationEngine.mutate(goldenImageDef, random, i);
                try {
                    Rp2350BootMetadata meta = RpBootMetadataParser.parseRp2350(mutation, 0x1000_0000L, false);
                    assertNotNull(meta);
                    accepted++;
                    outcomes.append(i).append(":ACCEPT:IMAGEDEF\n");
                } catch (DiagnosticException ex) {
                    Diagnostic diagnostic = ex.diagnostic();
                    diagnostics.merge(diagnostic.code(), 1, Integer::sum);
                    outcomes.append(i).append(':').append(diagnostic.code().id());
                    diagnostic.sourceRange().ifPresent(range ->
                            outcomes.append('@').append(range.offset()).append('+').append(range.length()));
                    outcomes.append('\n');
                } catch (Throwable t) {
                    throw new AssertionError("Crash on ImageDef mutation case " + i
                            + " (length " + mutation.length + "): " + t.getClass().getName() + " - " + t.getMessage(),
                            t);
                }
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        String outcomeHash = DeterministicMutationEngine.computeSha256(outcomes.toString());
        return new DeterministicMutationEngine.CampaignResult(
                count, accepted, count - accepted, outcomeHash, diagnostics, elapsed);
    }

    static byte[] createValidRp2040Boot2() {
        byte[] data = new byte[270];
        for (int i = 0; i < 252; i++) {
            data[i] = (byte) (i & 0xff);
        }
        long crc = Rp2040Boot2Checksum.calculate(data, 0, 252);
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(252, (int) crc);
        buf.putInt(256, 0x2004_0000); // Initial SP
        buf.putInt(260, 0x1000_0101); // Reset vector (Thumb mode bit 0 = 1)
        return data;
    }

    static byte[] createValidRp2350ImageDef() {
        byte[] data = new byte[64];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0, (int) RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        buf.putInt(4, 0x0000_0142); // TAG_IMAGE_TYPE (ARMv8-M Secure)
        buf.putInt(8, 0x0000_0043); // TAG_VECTOR_TABLE_OR_ENTRY
        buf.putInt(12, 0x1000_0100); // Vector table pointer
        buf.putInt(16, (int) RpBootMetadataParser.IMAGE_DEF_END_MAGIC);
        return data;
    }
}
