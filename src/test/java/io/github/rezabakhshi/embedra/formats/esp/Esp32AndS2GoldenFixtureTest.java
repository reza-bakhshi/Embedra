package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class Esp32AndS2GoldenFixtureTest {
    @Test
    void generatedFixturesMatchPinnedIndependentOracles() throws Exception {
        verify("esp32", 0, 0x4008_0008L,
            List.of(0x3f40_0020L, 0x3ffa_e000L, 0x4008_0000L));
        verify("esp32s2", 2, 0x4002_0008L,
            List.of(0x3f00_0020L, 0x3ffb_0000L, 0x4002_0000L));
    }

    private static void verify(String deviceId, int chipId, long entry,
            List<Long> addresses) throws Exception {
        String name = deviceId + "-freestanding-minimal";
        byte[] bytes = resource("/fixtures/" + deviceId + "/" + name + ".bin");
        String manifest = text("/fixtures/" + deviceId + "/" + name
            + ".bin.manifest.json");
        String oracle = text("/oracles/" + deviceId + "/" + name
            + ".expectations.json");
        EspImage image = EspImageParser.parseForChip(bytes, chipId,
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals(416, bytes.length);
        assertEquals(entry, image.header().entryPoint());
        assertEquals(addresses, image.segments().stream()
            .map(EspImageSegment::loadAddress).toList());
        assertEquals("embedra_t028_" + deviceId,
            EspAppDescriptionExtractor.extract(image).description().orElseThrow()
                .projectName());
        assertTrue(manifest.contains("\"sha256\": \"" + sha256(bytes) + "\""));
        assertTrue(oracle.contains("\"chipId\": " + chipId));
        assertTrue(oracle.contains("\"segmentCount\": 3"));
        addresses.forEach(address -> assertTrue(oracle.contains(String.format(
            "\"0x%08x\"", address))));
    }

    private static String text(String name) throws IOException {
        return new String(resource(name), StandardCharsets.UTF_8);
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream input = Esp32AndS2GoldenFixtureTest.class
                .getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("Missing T028 resource " + name);
            }
            return input.readAllBytes();
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(bytes));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }
}
