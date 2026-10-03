package io.github.rezabakhshi.embedra.analyzers.strings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MultiEncodingStringScannerTest {

    private MultiEncodingStringScanner scanner;

    @BeforeEach
    void setUp() {
        scanner = new MultiEncodingStringScanner();
    }

    @Test
    void extractsNullTerminatedAndBoundedAsciiStrings() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{0x00, 0x01, 0x02});
        out.write("Hello, World!\0".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{(byte) 0xFF, (byte) 0xFE});
        out.write("Firmware-v1.0.4-RELEASE".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0x00});

        byte[] data = out.toByteArray();
        List<ExtractedString> results = scanner.scan(data, 0x1000L);

        assertFalse(results.isEmpty());
        ExtractedString first = results.stream()
                .filter(s -> s.content().equals("Hello, World!"))
                .findFirst()
                .orElse(null);
        assertNotNull(first);
        assertEquals(StringEncoding.ASCII, first.encoding());
        assertEquals(StringConfidence.CONFIRMED, first.confidence());
        assertEquals(StringProvenance.STATIC_LITERAL, first.provenance());
        assertTrue(first.nullTerminated());
        assertEquals(0x1003L, first.offset());

        ExtractedString second = results.stream()
                .filter(s -> s.content().equals("Firmware-v1.0.4-RELEASE"))
                .findFirst()
                .orElse(null);
        assertNotNull(second);
        assertEquals(StringEncoding.ASCII, second.encoding());
        assertTrue(second.nullTerminated());
    }

    @Test
    void extractsValidUtf8WithMultibyteCharacters() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String utf8Text = "Embedded \u00e9\u00e8\u00ea \u4e2d\u6587 \u2602!\0";
        out.write(utf8Text.getBytes(StandardCharsets.UTF_8));

        byte[] data = out.toByteArray();
        List<ExtractedString> results = scanner.scan(data, 0x2000L);

        ExtractedString found = results.stream()
                .filter(s -> s.encoding() == StringEncoding.UTF_8)
                .findFirst()
                .orElse(null);
        assertNotNull(found);
        assertEquals("Embedded \u00e9\u00e8\u00ea \u4e2d\u6587 \u2602!", found.content());
        assertEquals(StringConfidence.CONFIRMED, found.confidence());
        assertTrue(found.nullTerminated());
    }

    @Test
    void rejectsOverlongAndSurrogateUtf8Sequences() throws Exception {
        byte[] overlongNul = new byte[]{(byte) 0xC0, (byte) 0x80, 'a', 'b', 'c'};
        List<ExtractedString> results = scanner.scan(overlongNul, 0x0L);
        assertTrue(results.isEmpty() || results.stream().noneMatch(s -> s.content().contains("\0")));

        byte[] surrogateHalf = new byte[]{(byte) 0xED, (byte) 0xA0, (byte) 0x80, 't', 'e', 's', 't'};
        results = scanner.scan(surrogateHalf, 0x0L);
        assertTrue(results.stream().noneMatch(s -> s.encoding() == StringEncoding.UTF_8 && s.content().length() > 4));
    }

    @Test
    void extractsUtf16LeAndBeStrings() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String textLe = "UTF-16 Little Endian Test\0";
        out.write(textLe.getBytes(StandardCharsets.UTF_16LE));

        byte[] padding = new byte[]{0x01, 0x02, 0x03, 0x04};
        out.write(padding);

        String textBe = "UTF-16 Big Endian Test\0";
        out.write(textBe.getBytes(StandardCharsets.UTF_16BE));

        byte[] data = out.toByteArray();
        List<ExtractedString> results = scanner.scan(data, 0x3000L);

        ExtractedString leString = results.stream()
                .filter(s -> s.encoding() == StringEncoding.UTF_16LE && s.content().contains("Little Endian"))
                .findFirst()
                .orElse(null);
        assertNotNull(leString);
        assertEquals("UTF-16 Little Endian Test", leString.content());
        assertEquals(StringConfidence.CONFIRMED, leString.confidence());

        ExtractedString beString = results.stream()
                .filter(s -> s.encoding() == StringEncoding.UTF_16BE && s.content().contains("Big Endian"))
                .findFirst()
                .orElse(null);
        assertNotNull(beString);
        assertEquals("UTF-16 Big Endian Test", beString.content());
    }

    @Test
    void extractsPascal8And16Strings() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Pascal 8-bit
        String pascal8 = "Short Pascal String";
        out.write((byte) pascal8.length());
        out.write(pascal8.getBytes(StandardCharsets.US_ASCII));
        out.write(0x00);

        // Pascal 16-bit
        String pascal16 = "A slightly longer 16-bit Pascal length-prefixed string";
        out.write((byte) (pascal16.length() & 0xFF));
        out.write((byte) ((pascal16.length() >> 8) & 0xFF));
        out.write(pascal16.getBytes(StandardCharsets.US_ASCII));

        byte[] data = out.toByteArray();
        List<ExtractedString> results = scanner.scan(data, 0x4000L);

        ExtractedString p8 = results.stream()
                .filter(s -> s.encoding() == StringEncoding.PASCAL_8)
                .findFirst()
                .orElse(null);
        assertNotNull(p8);
        assertEquals(pascal8, p8.content());

        ExtractedString p16 = results.stream()
                .filter(s -> s.encoding() == StringEncoding.PASCAL_16)
                .findFirst()
                .orElse(null);
        assertNotNull(p16);
        assertEquals(pascal16, p16.content());
    }

    @Test
    void filtersBinaryNoiseAndEnforcesLengthThreshold() throws Exception {
        byte[] noise = new byte[256];
        for (int i = 0; i < noise.length; i++) {
            noise[i] = (byte) (i & 0x1F); // non-printable control bytes
        }

        List<ExtractedString> results = scanner.scan(noise, 0x5000L);
        assertTrue(results.isEmpty());
    }

    @Test
    void enforcesResourceLimitsAndCancellation() {
        byte[] large = new byte[1024];

        ParserLimits tightInput = ParserLimits.defaults().withMaxAllocationBytes(512);
        DiagnosticException ex = assertThrows(
                DiagnosticException.class,
                () -> scanner.scan(large, 0x0L, StringScanOptions.defaults(), tightInput, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());

        CancellationToken cancelled = () -> true;
        DiagnosticException cancelEx = assertThrows(
                DiagnosticException.class,
                () -> scanner.scan(large, 0x0L, StringScanOptions.defaults(), ParserLimits.defaults(), cancelled));
        assertEquals(DiagnosticCode.CANCELLED, cancelEx.diagnostic().code());
    }

    @Test
    void redactsSensitiveStringsInLogs() {
        ExtractedString secretStr = new ExtractedString(
                0x1000L, 24, StringEncoding.ASCII, "FLAG{super_secret_ctf_flag}",
                StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL, true);
        assertEquals("FLA...g}", secretStr.redactedContent());

        ExtractedString shortStr = new ExtractedString(
                0x1000L, 4, StringEncoding.ASCII, "root",
                StringConfidence.LIKELY, StringProvenance.STATIC_LITERAL, true);
        assertEquals("root", shortStr.redactedContent());
    }
}
