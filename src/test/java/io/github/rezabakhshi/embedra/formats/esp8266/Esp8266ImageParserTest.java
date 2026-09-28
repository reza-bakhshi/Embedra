package io.github.rezabakhshi.embedra.formats.esp8266;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import org.junit.jupiter.api.Test;

class Esp8266ImageParserTest {
    private static final String FIXTURE_ROOT = "/fixtures/esp8266/";

    @Test
    void parsesVersion1WithoutClaimingTheRawIromCompanion() throws Exception {
        byte[] bytes = fixture("esp8266-freestanding-v1-0x00000.bin");
        Esp8266Image image = parse(bytes);

        assertEquals(Esp8266ImageVersion.VERSION_1, image.header().version());
        assertEquals(0x4010_0008L, image.header().entryPoint());
        assertEquals(2, image.segments().size());
        assertEquals(0x4010_0000L, image.segments().get(0).encodedLoadAddress());
        assertEquals(0x3ffe_8000L, image.segments().get(1).encodedLoadAddress());
        assertFalse(image.storedSdkCrc32().isPresent());
        assertEquals(Esp8266ImageDetection.MATCH, Esp8266ImageDetector.detect(bytes));
        assertEquals(Esp8266ImageDetection.NO_MATCH, Esp8266ImageDetector.detect(
            fixture("esp8266-freestanding-v1-0x01010.bin")));
    }

    @Test
    void parsesVersion2AndResolvesIromOnlyFromAnExplicitFlashBase() throws Exception {
        Esp8266Image image = parse(fixture("esp8266-freestanding-v2-0x01000.bin"));

        assertEquals(Esp8266ImageVersion.VERSION_2, image.header().version());
        assertEquals(3, image.segments().size());
        Esp8266ImageSegment irom = image.segments().get(0);
        assertTrue(irom.flashMapped());
        assertEquals(0, irom.encodedLoadAddress());
        assertEquals(0x4020_1010L, irom.resolveLoadAddress(0x1000));
        assertEquals(image.storedSdkCrc32(), image.calculatedSdkCrc32());
        assertThrows(IllegalArgumentException.class,
            () -> irom.resolveLoadAddress(0x1001));
    }

    @Test
    void rejectsMalformedCorpusWithTypedDiagnostics() throws IOException {
        assertDiagnostic(fixture("malformed/malformed-v1-checksum.bin"),
            DiagnosticCode.ESP8266_CHECKSUM_MISMATCH);
        assertDiagnostic(fixture("malformed/malformed-v2-crc.bin"),
            DiagnosticCode.ESP8266_CRC_MISMATCH);
        assertDiagnostic(fixture("malformed/malformed-v2-truncated-second-header.bin"),
            DiagnosticCode.ESP8266_SEGMENT_TRUNCATED);
    }

    @Test
    void rejectsConflictingNestedHeadersAndTrailingData() throws IOException {
        byte[] version2 = fixture("esp8266-freestanding-v2-0x01000.bin");
        version2[34] ^= 1;
        assertDiagnostic(version2, DiagnosticCode.ESP8266_HEADER_INVALID);

        byte[] version1 = fixture("esp8266-freestanding-v1-0x00000.bin");
        assertDiagnostic(Arrays.copyOf(version1, version1.length + 1),
            DiagnosticCode.ESP8266_TRAILING_DATA);
    }

    @Test
    void enforcesLimitsCancellationAndImmutableSegmentData() throws Exception {
        byte[] bytes = fixture("esp8266-freestanding-v1-0x00000.bin");
        ParserLimits inputLimit = new ParserLimits(bytes.length - 1L, 1024, 1024,
            16, 8, Duration.ofSeconds(1));
        assertDiagnostic(bytes, inputLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);

        ParserLimits objectLimit = new ParserLimits(bytes.length, 1024, 1024,
            1, 8, Duration.ofSeconds(1));
        assertDiagnostic(bytes, objectLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        assertDiagnostic(bytes, ParserLimits.defaults(), cancellation.token(),
            DiagnosticCode.CANCELLED);

        Esp8266Image image = parse(bytes);
        byte[] original = image.segments().get(0).data();
        byte[] changed = image.segments().get(0).data();
        changed[0] ^= 1;
        assertArrayEquals(original, image.segments().get(0).data());
    }

    @Test
    void distinguishesMalformedHeadersFromUnrelatedInputs() {
        assertEquals(Esp8266ImageDetection.NO_MATCH,
            Esp8266ImageDetector.detect(new byte[] {0x7f, 0x45, 0x4c, 0x46}));
        assertEquals(Esp8266ImageDetection.MALFORMED,
            Esp8266ImageDetector.detect(new byte[] {(byte) 0xe9, 0}));
        assertEquals(Esp8266ImageDetection.MALFORMED,
            Esp8266ImageDetector.detect(new byte[] {(byte) 0xea, 3, 0, 0, 0, 0, 0, 0}));
    }

    private static Esp8266Image parse(byte[] bytes) throws DiagnosticException {
        return Esp8266ImageParser.parse(bytes, ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static void assertDiagnostic(byte[] bytes, DiagnosticCode code) {
        assertDiagnostic(bytes, ParserLimits.defaults(), CancellationToken.none(), code);
    }

    private static void assertDiagnostic(byte[] bytes, ParserLimits limits,
            CancellationToken cancellationToken, DiagnosticCode code) {
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> Esp8266ImageParser.parse(bytes, limits, cancellationToken));
        assertEquals(code, failure.diagnostic().code());
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream input = Esp8266ImageParserTest.class.getResourceAsStream(
                FIXTURE_ROOT + name)) {
            assertTrue(input != null, "missing fixture " + name);
            return input.readAllBytes();
        }
    }
}
