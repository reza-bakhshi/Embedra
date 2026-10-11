package io.github.rezabakhshi.embedra.core.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32DfuImage;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32DfuParser;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.SplittableRandom;
import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;

/**
 * T071 Fuzz Campaign: At least 10,000 deterministic malformed inputs on STM32 DfuSe format.
 */
public class Stm32DfuBinaryFormatFuzzTest {

    public static final long SEED = 0xDF11_0483_0004L;

    public static final int CAMPAIGN_CASES = 10_000;

    @Test
    void runTenThousandDeterministicMalformedStm32DfuInputs() {
        byte[] golden = createValidDfu();
        assertNotNull(golden, "Golden DfuSe input must be generated");

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
                .allMatch(code -> code.id().startsWith("STM_") || code.id().startsWith("STM32_")
                        || code.id().startsWith("CORE_") || code.id().equals("LIMIT_EXCEEDED")),
                "All diagnostics must be valid STM or CORE codes");
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
                Stm32DfuImage dfu = Stm32DfuParser.parse(mutation, ParserLimits.defaults(), CancellationToken.none());
                assertNotNull(dfu);
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
                throw new AssertionError("Crash on STM32 DFU mutation case " + i + " (length " + mutation.length + "): "
                        + t.getClass().getName() + " - " + t.getMessage(), t);
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        String outcomeHash = DeterministicMutationEngine.computeSha256(outcomes.toString());
        return new DeterministicMutationEngine.CampaignResult(
                count, accepted, count - accepted, outcomeHash, diagnostics, elapsed);
    }

    static byte[] createValidDfu() {
        ByteArrayOutputStream elements = new ByteArrayOutputStream();
        writeU32(elements, 0x0800_0000L);
        writeU32(elements, 64);
        elements.writeBytes(new byte[64]);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes("Target".getBytes(StandardCharsets.US_ASCII));
        body.write(0);
        writeU32(body, 1);
        byte[] name = new byte[255];
        byte[] nameBytes = "Internal Flash".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, name, 0, nameBytes.length);
        body.writeBytes(name);
        writeU32(body, elements.size());
        writeU32(body, 1);
        body.writeBytes(elements.toByteArray());

        ByteArrayOutputStream file = new ByteArrayOutputStream();
        file.writeBytes("DfuSe".getBytes(StandardCharsets.US_ASCII));
        file.write(1);
        writeU32(file, 11 + body.size() + 16);
        file.write(1);
        file.writeBytes(body.toByteArray());
        writeU16(file, 0xffff);
        writeU16(file, 0xdf11);
        writeU16(file, 0x0483);
        writeU16(file, 0x011a);
        file.writeBytes("UFD".getBytes(StandardCharsets.US_ASCII));
        file.write(16);
        writeU32(file, 0);

        byte[] result = file.toByteArray();
        CRC32 crc = new CRC32();
        crc.update(result, 0, result.length - 4);
        writeU32(result, result.length - 4, ~crc.getValue() & 0xffff_ffffL);
        return result;
    }

    private static void writeU32(ByteArrayOutputStream output, long value) {
        for (int shift = 0; shift < 32; shift += 8) {
            output.write((int) (value >>> shift) & 0xff);
        }
    }

    private static void writeU32(byte[] bytes, int offset, long value) {
        for (int shift = 0; shift < 32; shift += 8) {
            bytes[offset + (shift / 8)] = (byte) ((value >>> shift) & 0xff);
        }
    }

    private static void writeU16(ByteArrayOutputStream output, int value) {
        output.write(value & 0xff);
        output.write((value >>> 8) & 0xff);
    }
}
