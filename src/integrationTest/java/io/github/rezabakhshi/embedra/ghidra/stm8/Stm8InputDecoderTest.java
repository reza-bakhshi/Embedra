package io.github.rezabakhshi.embedra.ghidra.stm8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit test suite verifying STM8 input decoding across raw BIN, Intel HEX, Motorola S-Record,
 * and ELF, as well as fail-closed validation on malformed inputs (T093).
 */
class Stm8InputDecoderTest {

    private static final Path FIXTURE_DIR = Path.of("src/test/resources/fixtures/stm8");

    private static final Path MALFORMED_DIR = FIXTURE_DIR.resolve("malformed");

    private static final List<String> REPRESENTATIVE_PARTS = List.of(
        "STM8S003F3P6", "STM8S103F3P6", "STM8S208RBT6",
        "STM8L151C8T6", "STM8L152R8T6", "STM8AF5288TAY",
        "STM8AL3188TA", "STM8T143AU"
    );

    @Test
    void allFourFormatsDecodeEquivalentlyForRepresentativeParts() throws IOException, Stm8MappingException {
        ParserLimits limits = ParserLimits.defaults();

        for (String part : REPRESENTATIVE_PARTS) {
            byte[] binBytes = Files.readAllBytes(FIXTURE_DIR.resolve(part + ".bin"));
            byte[] hexBytes = Files.readAllBytes(FIXTURE_DIR.resolve(part + ".hex"));
            byte[] srecBytes = Files.readAllBytes(FIXTURE_DIR.resolve(part + ".s19"));
            byte[] elfBytes = Files.readAllBytes(FIXTURE_DIR.resolve(part + ".elf"));

            Stm8InputDecoder.DecodedFirmware decodedBin = Stm8InputDecoder.decode(binBytes, limits);
            Stm8InputDecoder.DecodedFirmware decodedHex = Stm8InputDecoder.decode(hexBytes, limits);
            Stm8InputDecoder.DecodedFirmware decodedSrec = Stm8InputDecoder.decode(srecBytes, limits);
            Stm8InputDecoder.DecodedFirmware decodedElf = Stm8InputDecoder.decode(elfBytes, limits);

            assertEquals("RAW_BINARY", decodedBin.format());
            assertEquals("INTEL_HEX", decodedHex.format());
            assertEquals("MOTOROLA_S_RECORD", decodedSrec.format());
            assertEquals("ELF", decodedElf.format());

            assertEquals(0x008080L, decodedBin.entryPoint());
            assertEquals(0x008080L, decodedHex.entryPoint());
            assertEquals(0x008080L, decodedSrec.entryPoint());
            assertEquals(0x008080L, decodedElf.entryPoint());

            // Hex and S-Record map identically across the address space
            assertEquals(decodedHex.flashBytes().length, decodedSrec.flashBytes().length);
            assertTrue(decodedHex.flashBytes().length >= decodedBin.flashBytes().length);
            assertTrue(decodedElf.flashBytes().length >= decodedBin.flashBytes().length);

            // Verify vector table reset opcode 0x82 JPF
            assertEquals((byte) 0x82, decodedBin.flashBytes()[0]);
            assertEquals((byte) 0x82, decodedHex.flashBytes()[0]);
            assertEquals((byte) 0x82, decodedSrec.flashBytes()[0]);
            assertEquals((byte) 0x82, decodedElf.flashBytes()[0]);

            // Verify vector table targets match across all formats
            for (int i = 0; i < decodedBin.flashBytes().length; i++) {
                assertEquals(decodedBin.flashBytes()[i], decodedHex.flashBytes()[i]);
                assertEquals(decodedBin.flashBytes()[i], decodedSrec.flashBytes()[i]);
                assertEquals(decodedBin.flashBytes()[i], decodedElf.flashBytes()[i]);
            }
        }
    }

    @Test
    void malformedHexWithBadChecksumFailsClosed() throws IOException {
        byte[] bytes = Files.readAllBytes(MALFORMED_DIR.resolve("stm8s003_checksum.hex"));
        Stm8MappingException ex = assertThrows(Stm8MappingException.class, () ->
            Stm8InputDecoder.decode(bytes, ParserLimits.defaults()));
        assertEquals(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, ex.code());
        assertTrue(ex.getMessage().contains("checksum"));
    }

    @Test
    void malformedHexWithOverlappingRecordsFailsClosed() throws IOException {
        byte[] bytes = Files.readAllBytes(MALFORMED_DIR.resolve("stm8s208_overlapping.hex"));
        Stm8MappingException ex = assertThrows(Stm8MappingException.class, () ->
            Stm8InputDecoder.decode(bytes, ParserLimits.defaults()));
        assertEquals(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, ex.code());
        assertTrue(ex.getMessage().contains("checksum") || ex.getMessage().contains("Conflicting"));
    }

    @Test
    void malformedS19WithBadChecksumFailsClosed() throws IOException {
        byte[] bytes = Files.readAllBytes(MALFORMED_DIR.resolve("stm8l151_checksum.s19"));
        Stm8MappingException ex = assertThrows(Stm8MappingException.class, () ->
            Stm8InputDecoder.decode(bytes, ParserLimits.defaults()));
        assertEquals(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, ex.code());
        assertTrue(ex.getMessage().contains("checksum"));
    }

    @Test
    void emptyInputFailsClosed() {
        Stm8MappingException ex = assertThrows(Stm8MappingException.class, () ->
            Stm8InputDecoder.decode(new byte[0], ParserLimits.defaults()));
        assertEquals(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, ex.code());
    }
}
