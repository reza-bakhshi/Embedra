package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertTimeout;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class EspImageDeterministicFuzzTest {
    private static final long SEED = 0x454d_4245_4452_4131L;

    @Test
    void seededMalformedCampaignIsBoundedTypedAndExactlyReproducible() throws Exception {
        byte[] golden = fixture();

        EspImageFuzzCampaign.Result first = assertTimeout(Duration.ofSeconds(5),
            () -> EspImageFuzzCampaign.run(golden, SEED, 512));
        EspImageFuzzCampaign.Result repeated = assertTimeout(Duration.ofSeconds(5),
            () -> EspImageFuzzCampaign.run(golden, SEED, 512));
        EspImageFuzzCampaign.Result differentSeed = assertTimeout(Duration.ofSeconds(5),
            () -> EspImageFuzzCampaign.run(golden, SEED + 1, 512));

        assertEquals(first, repeated);
        assertEquals("8f35791f21d7f0b875d7c094657a768ba29aa38a725dda13242474242a113d23",
            first.outcomeSha256());
        assertNotEquals(first.outcomeSha256(), differentSeed.outcomeSha256());
        assertEquals(512, first.caseCount());
        assertEquals(512, first.acceptedCount() + first.rejectedCount());
        assertTrue(first.acceptedCount() > 0);
        assertTrue(first.rejectedCount() > 0);
        assertFalseOrTyped(first);
    }

    private static void assertFalseOrTyped(EspImageFuzzCampaign.Result result) {
        assertEquals(result.rejectedCount(), result.diagnosticCounts().values().stream()
            .mapToInt(Integer::intValue).sum());
        assertTrue(result.diagnosticCounts().keySet().stream()
            .allMatch(code -> code.id().startsWith("ESP_")
                || code.id().startsWith("CORE_")));
    }

    private static byte[] fixture() throws IOException {
        try (InputStream input = EspImageDeterministicFuzzTest.class.getResourceAsStream(
                "/fixtures/esp32s3/esp32s3-freestanding-minimal.bin")) {
            assertNotNull(input, "missing T008 fixture");
            return input.readAllBytes();
        }
    }
}
