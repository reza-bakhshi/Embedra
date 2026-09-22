package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class Esp32S3MalformedFixtureTest {
    private static final String FIXTURE_ROOT = "/fixtures/esp32s3/";

    private static final String MALFORMED_ROOT = FIXTURE_ROOT + "malformed/";

    private static final String ORACLE_ROOT = "/oracles/esp32s3/malformed/";

    private static final List<MutationCase> CASES = List.of(
        new MutationCase("malformed-truncated-segment-data", 350,
            "TRUNCATED_SEGMENT_DATA"),
        new MutationCase("malformed-segment-length-overflow", 400,
            "SEGMENT_LENGTH_OUT_OF_INPUT"),
        new MutationCase("malformed-overlapping-segments", 400,
            "OVERLAPPING_TARGET_RANGES"),
        new MutationCase("malformed-wrong-chip", 400, "CHIP_ID_MISMATCH"),
        new MutationCase("malformed-checksum", 400, "CHECKSUM_MISMATCH"),
        new MutationCase("malformed-digest", 432, "DIGEST_MISMATCH"),
        new MutationCase("malformed-entry-unaligned", 400,
            "INVALID_ENTRY_POINT_ALIGNMENT"),
        new MutationCase("malformed-trailing-data", 404,
            "UNEXPECTED_TRAILING_DATA")
    );

    @Test
    void malformedCorpusHasExactMutationsAndRejectionOracles() throws IOException {
        byte[] plain = readResource(FIXTURE_ROOT
            + "esp32s3-freestanding-minimal-no-digest.bin");
        byte[] digest = readResource(FIXTURE_ROOT + "esp32s3-freestanding-minimal.bin");

        for (MutationCase mutation : CASES) {
            byte[] fixture = readResource(MALFORMED_ROOT + mutation.name() + ".bin");
            String manifest = readString(MALFORMED_ROOT + mutation.name()
                + ".bin.manifest.json");
            String oracle = readString(ORACLE_ROOT + mutation.name()
                + ".expectations.json");

            assertEquals(mutation.size(), fixture.length, mutation.name());
            assertTrue(manifest.contains("\"sha256\": \"" + sha256(fixture) + "\""));
            assertTrue(oracle.contains("\"expectedOutcome\": \"REJECT\""));
            assertTrue(oracle.contains("\"expectedFailureClass\": \""
                + mutation.failureClass() + "\""));
        }

        assertArrayEquals(Arrays.copyOf(plain, 350), fixture("malformed-truncated-segment-data"));
        assertSingleMutation(plain, fixture("malformed-segment-length-overflow"), 344,
            new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
        assertSingleMutation(plain, fixture("malformed-overlapping-segments"), 328,
            new byte[] {0x00, 0x01, 0x01, 0x3c});
        assertSingleMutation(plain, fixture("malformed-wrong-chip"), 12,
            new byte[] {0x00, 0x00});
        assertSingleMutation(plain, fixture("malformed-checksum"), 399,
            new byte[] {0x5c});
        assertSingleMutation(digest, fixture("malformed-digest"), 400,
            new byte[] {0x31});
        assertSingleMutation(plain, fixture("malformed-entry-unaligned"), 4,
            new byte[] {0x09, (byte) 0x80, 0x37, 0x40});
        byte[] trailing = fixture("malformed-trailing-data");
        assertArrayEquals(plain, Arrays.copyOf(trailing, plain.length));
        assertArrayEquals(new byte[] {0x45, 0x4d, 0x42, 0x52},
            Arrays.copyOfRange(trailing, plain.length, trailing.length));
    }

    private static void assertSingleMutation(byte[] base, byte[] mutated, int offset,
            byte[] replacement) {
        byte[] expected = base.clone();
        System.arraycopy(replacement, 0, expected, offset, replacement.length);
        assertArrayEquals(expected, mutated);
    }

    private static byte[] fixture(String name) throws IOException {
        return readResource(MALFORMED_ROOT + name + ".bin");
    }

    private static String readString(String name) throws IOException {
        return new String(readResource(name), StandardCharsets.UTF_8);
    }

    private static byte[] readResource(String name) throws IOException {
        try (InputStream input = Esp32S3MalformedFixtureTest.class.getResourceAsStream(name)) {
            assertTrue(input != null, "missing T009 resource " + name);
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

    private record MutationCase(String name, int size, String failureClass) {
    }
}
