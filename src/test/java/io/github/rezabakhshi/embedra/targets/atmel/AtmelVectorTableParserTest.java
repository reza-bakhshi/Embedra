package io.github.rezabakhshi.embedra.targets.atmel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorEntry;
import io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorInstructionType;
import io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorTable;
import io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorTableParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Automated tests for AtmelVectorTableParser across AVR (JMP, RJMP) and SAM (Cortex-M) devices.
 */
class AtmelVectorTableParserTest {

    private static final Path FIXTURE_DIR = Path.of("src/test/resources/fixtures/atmel");

    private static final Path MALFORMED_DIR = FIXTURE_DIR.resolve("malformed");

    @Test
    void parseAtmega328pBinaryWithJmpVectors() throws IOException, DiagnosticException {
        byte[] bytes = Files.readAllBytes(FIXTURE_DIR.resolve("atmega328p_app.bin"));
        AtmelPartRecord part = AtmelPartRecord.defaultAtmega328p();

        AtmelVectorTable table = AtmelVectorTableParser.parse(
            bytes, part, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(table);
        assertEquals(26, table.entryCount());
        assertTrue(table.isConfident());

        // Reset vector
        AtmelVectorEntry reset = table.entries().getFirst();
        assertEquals(0, reset.slot().index());
        assertEquals(0x00000000L, reset.entryAddress());
        assertEquals(0x00000068L, reset.targetAddress());
        assertEquals(AtmelVectorInstructionType.JMP, reset.instructionType());
        assertTrue(reset.isValid());
        assertEquals("Reset_Handler", reset.canonicalLabel());

        assertTrue(table.resetEntry().isPresent());
        assertEquals(0x00000068L, table.resetEntry().get().targetAddress());
    }

    @Test
    void parseAttiny85BinaryWithRjmpVectors() throws IOException, DiagnosticException {
        byte[] bytes = Files.readAllBytes(FIXTURE_DIR.resolve("attiny85_app.bin"));
        AtmelPartRecord part = AtmelPartRecord.defaultAttiny85();

        AtmelVectorTable table = AtmelVectorTableParser.parse(
            bytes, part, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(table);
        assertEquals(15, table.entryCount());
        assertTrue(table.isConfident());

        // Reset vector
        AtmelVectorEntry reset = table.entries().getFirst();
        assertEquals(0, reset.slot().index());
        assertEquals(0x00000000L, reset.entryAddress());
        assertEquals(0x0000001EL, reset.targetAddress());
        assertEquals(AtmelVectorInstructionType.RJMP, reset.instructionType());
        assertTrue(reset.isValid());
        assertEquals("Reset_Handler", reset.canonicalLabel());
    }

    @Test
    void parseAtmega2560BinaryWithFiftySevenVectors() throws IOException, DiagnosticException {
        byte[] bytes = Files.readAllBytes(FIXTURE_DIR.resolve("atmega2560_app.bin"));
        AtmelPartRecord part = AtmelPartRecord.defaultAtmega2560();

        AtmelVectorTable table = AtmelVectorTableParser.parse(
            bytes, part, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(table);
        assertEquals(57, table.entryCount());
        assertTrue(table.isConfident());

        AtmelVectorEntry reset = table.entries().getFirst();
        assertEquals(0x000000E4L, reset.targetAddress());
        assertEquals(AtmelVectorInstructionType.JMP, reset.instructionType());
        assertTrue(reset.isValid());
    }

    @Test
    void parseSamd21CortexMVectorTable() throws IOException, DiagnosticException {
        byte[] bytes = Files.readAllBytes(FIXTURE_DIR.resolve("samd21g18a_app.bin"));
        AtmelPartRecord part = AtmelPartRecord.defaultSamd21g18a();

        AtmelVectorTable table = AtmelVectorTableParser.parse(
            bytes, part, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(table);
        assertEquals(44, table.entryCount());
        assertTrue(table.isConfident());

        // Initial SP
        AtmelVectorEntry sp = table.entries().get(0);
        assertEquals(AtmelVectorInstructionType.INITIAL_SP, sp.instructionType());
        assertEquals(0x20008000L, sp.targetAddress());
        assertTrue(sp.isValid());

        // Reset Handler
        AtmelVectorEntry reset = table.entries().get(1);
        assertEquals(AtmelVectorInstructionType.THUMB_VECTOR, reset.instructionType());
        assertEquals(0x000000C0L, reset.targetAddress());
        assertTrue(reset.isValid());
        assertEquals("Reset_Handler", reset.canonicalLabel());
    }

    @Test
    void parseSame70CortexMVectorTable() throws IOException, DiagnosticException {
        byte[] bytes = Files.readAllBytes(FIXTURE_DIR.resolve("same70q21_app.bin"));
        AtmelPartRecord part = AtmelPartRecord.defaultSame70q21();

        AtmelVectorTable table = AtmelVectorTableParser.parse(
            bytes, 0, 0x00400000L, part, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(table);
        assertEquals(85, table.entryCount());
        assertTrue(table.isConfident());

        AtmelVectorEntry sp = table.entries().get(0);
        assertEquals(0x20460000L, sp.targetAddress());
        assertTrue(sp.isValid());

        AtmelVectorEntry reset = table.entries().get(1);
        assertEquals(0x00400200L, reset.targetAddress());
        assertTrue(reset.isValid());
    }

    @Test
    void parseOptibootBootloaderResetVector() throws IOException, DiagnosticException {
        byte[] bytes = Files.readAllBytes(FIXTURE_DIR.resolve("atmega328p_optiboot.bin"));
        AtmelPartRecord part = AtmelPartRecord.defaultAtmega328p();

        // Optiboot starts at 0x7E00
        AtmelVectorTable table = AtmelVectorTableParser.parse(
            bytes, 0, 0x00007E00L, part, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(table);
        AtmelVectorEntry reset = table.entries().getFirst();
        assertEquals(0x00007E00L, reset.entryAddress());
        assertEquals(0x00007E08L, reset.targetAddress());
        assertEquals(AtmelVectorInstructionType.JMP, reset.instructionType());
        assertTrue(reset.isValid());
    }

    @Test
    void malformedInputsHandledGracefully() throws Exception {
        // 1. Invalid vector table opcodes
        byte[] badVec = Files.readAllBytes(MALFORMED_DIR.resolve("attiny85_invalid_vector.bin"));
        try {
            AtmelVectorTable badTable = AtmelVectorTableParser.parse(
                badVec, AtmelPartRecord.defaultAttiny85(), ParserLimits.defaults(), CancellationToken.none());
            assertFalse(badTable.isConfident());
            assertFalse(badTable.resetEntry().isPresent());
        } catch (DiagnosticException e) {
            assertTrue(e.diagnostic().code() == DiagnosticCode.ATMEL_VECTOR_TABLE_INVALID
                || e.diagnostic().code() == DiagnosticCode.INVALID_MODEL);
        }

        // 2. Bad initial SP
        byte[] badSp = Files.readAllBytes(MALFORMED_DIR.resolve("samd21_bad_sp.bin"));
        AtmelVectorTable spTable = AtmelVectorTableParser.parse(
            badSp, AtmelPartRecord.defaultSamd21g18a(), ParserLimits.defaults(), CancellationToken.none());
        assertFalse(spTable.entries().getFirst().isValid(), "Initial SP outside SRAM should be invalid");

        // 3. Truncated binary smaller than required table size throws
        byte[] trunc = Files.readAllBytes(MALFORMED_DIR.resolve("same70_truncated.bin"));
        DiagnosticException de = assertThrows(DiagnosticException.class, () ->
            AtmelVectorTableParser.parse(
                trunc, AtmelPartRecord.defaultSame70q21(), ParserLimits.defaults(), CancellationToken.none())
        );
        assertEquals(DiagnosticCode.ATMEL_VECTOR_TABLE_TRUNCATED, de.diagnostic().code());
    }

    @Test
    void cancellationThrowsDiagnosticException() {
        byte[] dummy = new byte[256];
        CancellationToken token = () -> true;
        assertThrows(DiagnosticException.class, () ->
            AtmelVectorTableParser.parse(
                dummy, AtmelPartRecord.defaultAtmega328p(), ParserLimits.defaults(), token)
        );
    }
}
