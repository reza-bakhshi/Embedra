package io.github.rezabakhshi.embedra.core.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32VectorDiscovery;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/**
 * T071 Fuzz Campaign: At least 10,000 deterministic malformed inputs on STM32 raw binary vector discovery.
 */
public class Stm32VectorDiscoveryBinaryFormatFuzzTest {

    public static final long SEED = 0xF103_C800_0005L;

    public static final int CAMPAIGN_CASES = 10_000;

    private static final long IMAGE_BASE = 0x0800_0000L;

    private static final List<Stm32VectorDiscovery.AddressRange> RAM_RANGES = List.of(
            new Stm32VectorDiscovery.AddressRange(0x2000_0000L, 0x2001_0000L)
    );

    @Test
    void runTenThousandDeterministicMalformedVectorDiscoveryInputs() {
        byte[] golden = createValidVectorTable();
        assertNotNull(golden, "Golden vector table input must be generated");

        CampaignResult result = runCampaign(golden, SEED, CAMPAIGN_CASES);

        assertEquals(CAMPAIGN_CASES, result.totalCases());
        assertTrue(result.candidatesFoundCount() > 0, "Must discover candidates on golden mutations");
        assertTrue(result.noCandidatesCount() > 0, "Must safely reject/find zero candidates on malformed inputs");

        // Repeat run with identical seed to prove 100% deterministic reproducibility
        CampaignResult repeatResult = runCampaign(golden, SEED, CAMPAIGN_CASES);
        assertEquals(result.outcomeSha256(), repeatResult.outcomeSha256(),
                "Outcome digest must be bit-for-bit identical");
    }

    public record CampaignResult(
            int totalCases,
            int candidatesFoundCount,
            int noCandidatesCount,
            String outcomeSha256,
            long elapsedMillis) {
    }

    public static CampaignResult runCampaign(byte[] golden, long seed, int count) {
        SplittableRandom random = new SplittableRandom(seed);
        StringBuilder outcomes = new StringBuilder(count * 32);
        int withCandidates = 0;
        int noCandidates = 0;
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < count; i++) {
            byte[] mutation = DeterministicMutationEngine.mutate(golden, random, i);
            try {
                List<Stm32VectorDiscovery.Candidate> candidates = Stm32VectorDiscovery.discover(
                        mutation, IMAGE_BASE, RAM_RANGES, ParserLimits.defaults(), CancellationToken.none());
                if (!candidates.isEmpty()) {
                    withCandidates++;
                    outcomes.append(i).append(":CANDIDATES:").append(candidates.size()).append('\n');
                } else {
                    noCandidates++;
                    outcomes.append(i).append(":EMPTY\n");
                }
            } catch (IllegalArgumentException ex) {
                // Handled bounded rejection (e.g. invalid length or limit exceeded)
                noCandidates++;
                outcomes.append(i).append(":REJECTED:").append(ex.getMessage()).append('\n');
            } catch (Throwable t) {
                throw new AssertionError("Crash on Vector Discovery mutation case " + i
                        + " (length " + mutation.length + "): " + t.getClass().getName() + " - " + t.getMessage(), t);
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        String outcomeHash = DeterministicMutationEngine.computeSha256(outcomes.toString());
        return new CampaignResult(count, withCandidates, noCandidates, outcomeHash, elapsed);
    }

    static byte[] createValidVectorTable() {
        byte[] data = new byte[128];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0, 0x2000_5000); // Initial SP inside RAM range
        buf.putInt(4, 0x0800_0041); // Reset vector (Thumb mode bit 0 = 1, inside image)
        for (int i = 2; i < 16; i++) {
            buf.putInt(i * 4, 0x0800_0041 + (i * 2)); // Valid handler pointers
        }
        return data;
    }
}
