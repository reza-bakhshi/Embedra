package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class Esp32S3PartitionFixtureTest {
    private static final String FIXTURE_ROOT = "/fixtures/esp32s3/full-flash/";

    private static final String ORACLE_ROOT = "/oracles/esp32s3/full-flash/";

    private static final int FLASH_SIZE = 0x80000;

    @Test
    void fixtureMatrixHasAdjacentProvenanceAndIndependentOracles() throws Exception {
        for (String name : List.of("default-factory", "custom-offset-misleading-magic",
                "ota-custom-encrypted", "invalid-partition-md5")) {
            byte[] flash = resource(FIXTURE_ROOT + name + ".bin");
            String manifest = text(FIXTURE_ROOT + name + ".bin.manifest.json");
            String expectation = text(ORACLE_ROOT + name + ".expectations.json");

            assertEquals(FLASH_SIZE, flash.length, name);
            assertTrue(manifest.contains("\"fixtureId\": "
                + "\"esp32s3.full-flash." + name + "\""), name);
            assertTrue(manifest.contains("\"sha256\": \"" + sha256(flash) + "\""),
                name);
            assertTrue(manifest.contains("\"redistributionStatus\": "
                + "\"REDISTRIBUTABLE\""), name);
            assertTrue(manifest.contains("\"T018\""), name);
            assertTrue(expectation.contains("\"flashSize\": 524288"), name);
        }
    }

    @Test
    void defaultFixtureContainsExactTableAndApplicationAtFlashOffsets()
            throws Exception {
        byte[] flash = resource(FIXTURE_ROOT + "default-factory.bin");
        byte[] app = resource("/fixtures/esp32s3/esp32s3-freestanding-minimal.bin");

        assertEntry(flash, 0x8000, "nvs", 0x01, 0x02, 0x9000, 0x6000, 0);
        assertEntry(flash, 0x8020, "phy_init", 0x01, 0x01, 0xf000, 0x1000, 0);
        assertEntry(flash, 0x8040, "factory", 0x00, 0x00, 0x10000, 0x20000, 0);
        assertEntry(flash, 0x8060, "storage", 0x01, 0x82, 0x30000, 0x10000, 0);
        assertEquals(0xeb, Byte.toUnsignedInt(flash[0x8080]));
        assertEquals(0xeb, Byte.toUnsignedInt(flash[0x8081]));
        assertArrayEquals(app, java.util.Arrays.copyOfRange(flash, 0x10000,
            0x10000 + app.length));
    }

    @Test
    void customOffsetFixtureRetainsMisleadingMagicBeforeValidatedTable()
            throws Exception {
        byte[] flash = resource(FIXTURE_ROOT + "custom-offset-misleading-magic.bin");
        String expectation = text(ORACLE_ROOT
            + "custom-offset-misleading-magic.expectations.json");

        assertEquals(0xaa, Byte.toUnsignedInt(flash[0x6000]));
        assertEquals(0x50, Byte.toUnsignedInt(flash[0x6001]));
        assertEquals(0xaa, Byte.toUnsignedInt(flash[0x8000]));
        assertEquals(0x50, Byte.toUnsignedInt(flash[0x8001]));
        assertEntry(flash, 0x10000, "nvs", 0x01, 0x02, 0x11000, 0x5000, 0);
        assertEntry(flash, 0x10020, "factory", 0x00, 0x00, 0x20000, 0x20000, 0);
        assertEquals(0xe9, Byte.toUnsignedInt(flash[0x7000]));
        assertTrue(expectation.contains("\"partitionTableOffset\": 65536"));
        assertTrue(expectation.replaceAll("\\s", "")
            .contains("\"misleadingOffsets\":[24576,32768,28672]"));
    }

    @Test
    void otaFixtureCoversOtaSlotsCustomTypeAndEncryptedFlag() throws Exception {
        byte[] flash = resource(FIXTURE_ROOT + "ota-custom-encrypted.bin");

        assertEntry(flash, 0x8020, "otadata", 0x01, 0x00, 0xd000, 0x2000, 0);
        assertEntry(flash, 0x8060, "ota_0", 0x00, 0x10, 0x10000, 0x20000, 0);
        assertEntry(flash, 0x8080, "ota_1", 0x00, 0x11, 0x30000, 0x20000, 0);
        assertEntry(flash, 0x80a0, "assets", 0x40, 0x7f, 0x50000, 0x10000, 1);
    }

    @Test
    void invalidMd5FixtureIsOneDigestByteMutationOfDefault() throws Exception {
        byte[] valid = resource(FIXTURE_ROOT + "default-factory.bin");
        byte[] invalid = resource(FIXTURE_ROOT + "invalid-partition-md5.bin");
        int differences = 0;
        int differenceOffset = -1;
        for (int index = 0; index < valid.length; index++) {
            if (valid[index] != invalid[index]) {
                differences++;
                differenceOffset = index;
            }
        }

        assertEquals(1, differences);
        assertEquals(0x8090, differenceOffset);
        assertTrue(text(ORACLE_ROOT + "invalid-partition-md5.expectations.json")
            .contains("\"expectedOutcome\": \"REJECT_INVALID_MD5\""));
    }

    private static void assertEntry(byte[] flash, int offset, String label, int type,
            int subtype, long flashOffset, long size, long flags) {
        assertEquals(0xaa, Byte.toUnsignedInt(flash[offset]));
        assertEquals(0x50, Byte.toUnsignedInt(flash[offset + 1]));
        assertEquals(type, Byte.toUnsignedInt(flash[offset + 2]));
        assertEquals(subtype, Byte.toUnsignedInt(flash[offset + 3]));
        assertEquals(flashOffset, unsignedInt(flash, offset + 4));
        assertEquals(size, unsignedInt(flash, offset + 8));
        int labelLength = 0;
        while (labelLength < 16 && flash[offset + 12 + labelLength] != 0) {
            labelLength++;
        }
        assertEquals(label, new String(flash, offset + 12, labelLength,
            StandardCharsets.UTF_8));
        assertEquals(flags, unsignedInt(flash, offset + 28));
    }

    private static long unsignedInt(byte[] data, int offset) {
        return Integer.toUnsignedLong(Byte.toUnsignedInt(data[offset])
            | Byte.toUnsignedInt(data[offset + 1]) << 8
            | Byte.toUnsignedInt(data[offset + 2]) << 16
            | Byte.toUnsignedInt(data[offset + 3]) << 24);
    }

    private static String text(String path) throws IOException {
        return new String(resource(path), StandardCharsets.UTF_8);
    }

    private static byte[] resource(String path) throws IOException {
        try (InputStream input = Esp32S3PartitionFixtureTest.class.getResourceAsStream(path)) {
            assertNotNull(input, "missing resource " + path);
            return input.readAllBytes();
        }
    }

    private static String sha256(byte[] input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
