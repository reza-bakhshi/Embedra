package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class Esp32S3GoldenFixtureTest {
    private static final String FIXTURE_ROOT = "/fixtures/esp32s3/";

    private static final String ORACLE_ROOT = "/oracles/esp32s3/";

    private static final String DIGEST_FIXTURE = "esp32s3-freestanding-minimal";

    private static final String NO_DIGEST_FIXTURE =
        "esp32s3-freestanding-minimal-no-digest";

    @Test
    void goldenApplicationsHavePinnedBinariesAndIndependentOracles() throws IOException {
        verifyFixture(DIGEST_FIXTURE, 432, true);
        verifyFixture(NO_DIGEST_FIXTURE, 400, false);
    }

    private static void verifyFixture(String fixtureName, int expectedSize,
            boolean digestAppended) throws IOException {
        String fixture = FIXTURE_ROOT + fixtureName + ".bin";
        byte[] image = readResource(fixture);
        String manifest = new String(readResource(fixture + ".manifest.json"),
            StandardCharsets.UTF_8);
        String expectations = new String(readResource(
            ORACLE_ROOT + fixtureName + ".expectations.json"), StandardCharsets.UTF_8);

        assertEquals(expectedSize, image.length);
        assertEquals(0xe9, Byte.toUnsignedInt(image[0]), "ESP image magic");
        assertEquals(3, Byte.toUnsignedInt(image[1]), "segment count");
        assertEquals(9, Byte.toUnsignedInt(image[12]), "ESP32-S3 chip ID low byte");
        assertEquals(0, Byte.toUnsignedInt(image[13]), "ESP32-S3 chip ID high byte");
        assertTrue(manifest.contains("\"sha256\": \"" + sha256(image) + "\""));
        assertTrue(manifest.contains("\"fixtureId\": "
            + "\"esp32s3.esptool-v5.4.0." + fixtureName + "\""));
        assertTrue(expectations.contains("\"esptoolVersion\": \"5.4.0\""));
        assertTrue(expectations.contains("\"elfMachine\": \"Tensilica Xtensa Processor\""));
        assertTrue(expectations.contains("\"chipId\": 9"));
        assertTrue(expectations.contains("\"entryPoint\": \"0x40378008\""));
        assertTrue(expectations.contains("\"segmentCount\": 3"));
        assertTrue(expectations.contains("\"loadAddress\": \"0x3c010020\""));
        assertTrue(expectations.contains("\"loadAddress\": \"0x3fc88000\""));
        assertTrue(expectations.contains("\"loadAddress\": \"0x40378000\""));
        assertTrue(expectations.contains("\"projectName\": \"embedra_t008_fixture\""));
        assertTrue(expectations.contains("\"digestAppended\": " + digestAppended));
        assertTrue(expectations.contains(digestAppended
            ? "\"digestValid\": true" : "\"digestValid\": null"));
    }

    private static byte[] readResource(String name) throws IOException {
        try (InputStream input = Esp32S3GoldenFixtureTest.class.getResourceAsStream(name)) {
            assertTrue(input != null, "missing T008 resource " + name);
            return input.readAllBytes();
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }
}
