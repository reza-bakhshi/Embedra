package io.github.rezabakhshi.embedra.formats.rp.uf2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;

public class RpUf2ParserTest {

    private static final Path FIXTURES_DIR = Path.of("src/test/resources/fixtures/rp");

    @Test
    void testParseRp2040Uf2() throws Exception {
        Path path = FIXTURES_DIR.resolve("rp2040-pico-blinky.uf2");
        RpUf2Image image = RpUf2Parser.parse(path, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(image);
        assertEquals(RpUf2Family.RP2040, image.family());
        assertEquals("RP2040", image.family().chip());
        assertEquals(0x10000000L, image.baseTargetAddress());
        assertFalse(image.blocks().isEmpty());

        byte[] flatBin = image.extractContinuousBinary();
        assertTrue(flatBin.length > 0);
        // Verify boot2 entry header inside extracted binary
        assertEquals(256, image.blocks().get(0).payloadSize());
    }

    @Test
    void testParseRp2350ArmUf2() throws Exception {
        Path path = FIXTURES_DIR.resolve("rp2350-arm-pico2.uf2");
        RpUf2Image image = RpUf2Parser.parse(path, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(image);
        assertEquals(RpUf2Family.RP2350_ARM_SECURE, image.family());
        assertEquals("RP2350", image.family().chip());
        assertEquals(0x10000000L, image.baseTargetAddress());
    }

    @Test
    void testParseRp2350RiscvUf2() throws Exception {
        Path path = FIXTURES_DIR.resolve("rp2350-riscv-pico2.uf2");
        RpUf2Image image = RpUf2Parser.parse(path, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(image);
        assertEquals(RpUf2Family.RP2350_RISCV, image.family());
        assertEquals("RP2350", image.family().chip());
        assertEquals("RV32IMAC", image.family().architecture());
        assertEquals(0x10000000L, image.baseTargetAddress());
    }

    @Test
    void testMalformedCorruptedMagic() {
        Path path = FIXTURES_DIR.resolve("malformed/uf2-corrupted-magic.uf2");
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpUf2Parser.parse(path, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.RP_UF2_MAGIC_MISMATCH, ex.diagnostic().code());
    }

    @Test
    void testMalformedTruncatedBlock() {
        Path path = FIXTURES_DIR.resolve("malformed/uf2-truncated-block.uf2");
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpUf2Parser.parse(path, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.RP_UF2_INVALID, ex.diagnostic().code());
    }

    @Test
    void testMalformedFamilyMismatch() {
        Path path = FIXTURES_DIR.resolve("malformed/uf2-family-mismatch.uf2");
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpUf2Parser.parse(path, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.RP_UF2_FAMILY_MISMATCH, ex.diagnostic().code());
    }

    @Test
    void testLimitsExceeded() throws IOException {
        Path path = FIXTURES_DIR.resolve("rp2040-pico-blinky.uf2");
        byte[] bytes = Files.readAllBytes(path);

        ParserLimits tightLimits = new ParserLimits(100, 100, 100, 100, 10, Duration.ofSeconds(1));
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpUf2Parser.parse(path, tightLimits, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void testCancellation() {
        Path path = FIXTURES_DIR.resolve("rp2040-pico-blinky.uf2");
        CancellationToken token = () -> true; // always cancelled
        assertThrows(DiagnosticException.class, () ->
                RpUf2Parser.parse(path, ParserLimits.defaults(), token));
    }

    @Test
    void testNonExistentFileAndInvalidLengthAndObjectLimit() {
        assertThrows(DiagnosticException.class, () ->
                RpUf2Parser.parse(Path.of("nonexistent-file.uf2"), ParserLimits.defaults(), CancellationToken.none()));

        assertThrows(DiagnosticException.class, () ->
                RpUf2Parser.parse(new byte[100], ParserLimits.defaults(), CancellationToken.none()));

        byte[] twoBlocks = new byte[1024];
        ParserLimits oneObjLimit = new ParserLimits(100_000, 100_000, 100_000, 1, 10, Duration.ofSeconds(5));
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpUf2Parser.parse(twoBlocks, oneObjLimit, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }
}
