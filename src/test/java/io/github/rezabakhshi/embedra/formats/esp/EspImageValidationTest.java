package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class EspImageValidationTest {
    private static final String FIXTURE_ROOT = "/fixtures/esp32s3/";

    private static final int ESP32_S3_CHIP_ID = 9;

    @ParameterizedTest(name = "{0} -> {1}")
    @MethodSource("malformedImages")
    void rejectsMalformedCorpusWithStableTypedDiagnostics(String fixture,
            DiagnosticCode expectedCode, long expectedOffset) throws IOException {
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> parse(fixture));

        assertEquals(expectedCode, failure.diagnostic().code());
        assertTrue(failure.diagnostic().sourceRange().isPresent());
        assertEquals(expectedOffset,
            failure.diagnostic().sourceRange().orElseThrow().offset());
    }

    @Test
    void rejectsWrongMagicAndMalformedHeaderWithoutGuessing() throws IOException {
        byte[] valid = fixture("esp32s3-freestanding-minimal.bin");
        valid[0] = 0;
        assertDiagnostic(valid, DiagnosticCode.ESP_MAGIC_INVALID);

        assertDiagnostic(new byte[] {(byte) 0xe9, 3, 2},
            DiagnosticCode.ESP_HEADER_TRUNCATED);

        valid = fixture("esp32s3-freestanding-minimal.bin");
        valid[23] = 2;
        assertDiagnostic(valid, DiagnosticCode.ESP_HEADER_INVALID);
    }

    @Test
    void enforcesResourceLimitsAndCancellationBeforeLargeReads() throws IOException {
        byte[] valid = fixture("esp32s3-freestanding-minimal.bin");
        ParserLimits inputLimit = new ParserLimits(valid.length - 1L, 16 * 1024 * 1024,
            16 * 1024 * 1024, 16, 8, Duration.ofSeconds(1));
        assertDiagnostic(valid, inputLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);

        ParserLimits allocationLimit = ParserLimits.defaults().withMaxAllocationBytes(128);
        assertDiagnostic(valid, allocationLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        assertDiagnostic(valid, ParserLimits.defaults(), cancellation.token(),
            DiagnosticCode.CANCELLED);
    }

    @Test
    void genericParsingPreservesChipIdentityWithoutSilentlySelectingATarget()
            throws Exception {
        EspImage image = EspImageParser.parse(
            fixture("malformed-wrong-chip.bin"), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals(0, image.header().chipId());
    }

    @Test
    void rejectsAdditionalTruncationAndEntryBoundaryCases() throws IOException {
        byte[] plain = fixture("esp32s3-freestanding-minimal-no-digest.bin");
        assertDiagnostic(Arrays.copyOf(plain, 330),
            DiagnosticCode.ESP_SEGMENT_HEADER_TRUNCATED);
        assertDiagnostic(Arrays.copyOf(plain, 399),
            DiagnosticCode.ESP_SEGMENT_TRUNCATED);

        byte[] digestTruncated = plain.clone();
        digestTruncated[23] = 1;
        assertDiagnostic(digestTruncated, DiagnosticCode.ESP_DIGEST_TRUNCATED);

        byte[] outsideEntry = plain.clone();
        Arrays.fill(outsideEntry, 4, 8, (byte) 0);
        assertDiagnostic(outsideEntry, DiagnosticCode.ESP_ENTRY_INVALID);

        byte[] invalidSegmentCount = plain.clone();
        invalidSegmentCount[1] = 0;
        assertDiagnostic(invalidSegmentCount, DiagnosticCode.ESP_HEADER_INVALID);
    }

    @Test
    void rejectsSegmentCountsAboveTheConfiguredObjectLimit() throws IOException {
        byte[] valid = fixture("esp32s3-freestanding-minimal.bin");
        ParserLimits objectLimit = new ParserLimits(valid.length, 16 * 1024 * 1024,
            16 * 1024 * 1024, 2, 8, Duration.ofSeconds(1));

        assertDiagnostic(valid, objectLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);
    }

    private static Stream<Arguments> malformedImages() {
        return Stream.of(
            Arguments.of("malformed-truncated-segment-data.bin",
                DiagnosticCode.ESP_SEGMENT_TRUNCATED, 348L),
            Arguments.of("malformed-segment-length-overflow.bin",
                DiagnosticCode.ESP_SEGMENT_LENGTH_INVALID, 344L),
            Arguments.of("malformed-overlapping-segments.bin",
                DiagnosticCode.ESP_SEGMENT_OVERLAP, 328L),
            Arguments.of("malformed-wrong-chip.bin",
                DiagnosticCode.ESP_CHIP_MISMATCH, 12L),
            Arguments.of("malformed-checksum.bin",
                DiagnosticCode.ESP_CHECKSUM_MISMATCH, 399L),
            Arguments.of("malformed-digest.bin",
                DiagnosticCode.ESP_DIGEST_MISMATCH, 400L),
            Arguments.of("malformed-entry-unaligned.bin",
                DiagnosticCode.ESP_ENTRY_INVALID, 4L),
            Arguments.of("malformed-trailing-data.bin",
                DiagnosticCode.ESP_TRAILING_DATA, 400L));
    }

    private static EspImage parse(String fixture) throws IOException, DiagnosticException {
        return EspImageParser.parseForChip(fixture(fixture), ESP32_S3_CHIP_ID,
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static void assertDiagnostic(byte[] input, DiagnosticCode code) {
        assertDiagnostic(input, ParserLimits.defaults(), CancellationToken.none(), code);
    }

    private static void assertDiagnostic(byte[] input, ParserLimits limits,
            CancellationToken cancellationToken, DiagnosticCode code) {
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> EspImageParser.parseForChip(input, ESP32_S3_CHIP_ID, limits,
                cancellationToken));
        assertEquals(code, failure.diagnostic().code());
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream input = EspImageValidationTest.class.getResourceAsStream(
                FIXTURE_ROOT + (name.startsWith("malformed-") ? "malformed/" : "") + name)) {
            assertTrue(input != null, "missing fixture " + name);
            return input.readAllBytes();
        }
    }
}
