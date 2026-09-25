package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class Esp32C3GoldenFixtureTest {
    @Test
    void pinsIndependentRiscVFixtureAndOracle() throws Exception {
        byte[] binary = resource("/fixtures/esp32c3/esp32c3-freestanding-minimal.bin");
        EspImage image = EspImageParser.parse(binary, ParserLimits.defaults(),
            CancellationToken.none());
        String manifest = new String(resource(
            "/fixtures/esp32c3/esp32c3-freestanding-minimal.bin.manifest.json"),
            StandardCharsets.UTF_8);
        String oracle = new String(resource(
            "/oracles/esp32c3/esp32c3-freestanding-minimal.expectations.json"),
            StandardCharsets.UTF_8);

        assertEquals(5, image.header().chipId());
        assertEquals(0x4200_0000L, image.header().entryPoint());
        assertEquals(4, image.segments().size());
        assertEquals(3, image.segments().stream()
            .filter(segment -> !segment.isAlignmentPadding()).count());
        assertTrue(manifest.contains(HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(binary))));
        assertTrue(oracle.contains("\"elfMachine\": \"RISC-V\""));
        assertTrue(oracle.contains("\"projectName\": \"embedra_t029_esp32c3\""));
    }

    private static byte[] resource(String name) throws Exception {
        try (InputStream input = Esp32C3GoldenFixtureTest.class.getResourceAsStream(name)) {
            assertTrue(input != null, "missing fixture resource " + name);
            return input.readAllBytes();
        }
    }
}
