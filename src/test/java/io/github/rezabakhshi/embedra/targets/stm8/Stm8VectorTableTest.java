package io.github.rezabakhshi.embedra.targets.stm8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8CatalogRegistry;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import io.github.rezabakhshi.embedra.targets.stm8.vector.Stm8VectorEntry;
import io.github.rezabakhshi.embedra.targets.stm8.vector.Stm8VectorSlot;
import io.github.rezabakhshi.embedra.targets.stm8.vector.Stm8VectorTable;
import io.github.rezabakhshi.embedra.targets.stm8.vector.Stm8VectorTableParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Unit test suite for STM8 interrupt vector table parsing, scoring, entry-point resolution, and label generation.
 */
class Stm8VectorTableTest {

    private static final Path FIXTURES_DIR = Path.of("src/test/resources/fixtures/stm8");

    private static final Path MALFORMED_DIR = FIXTURES_DIR.resolve("malformed");

    private static final List<String> REPRESENTATIVE_PARTS = List.of(
        "STM8S003F3P6", "STM8S103F3P6", "STM8S208RBT6",
        "STM8L151C8T6", "STM8L152R8T6", "STM8AF5288TAY",
        "STM8AL3188TA", "STM8T143AU"
    );

    private static Stm8CatalogRegistry registry;

    @BeforeAll
    static void setUp() throws Exception {
        registry = Stm8CatalogRegistry.loadDefault();
    }

    @Test
    void parseValidVectorTablesAcrossAllRepresentativeParts() throws IOException, DiagnosticException {
        for (String pn : REPRESENTATIVE_PARTS) {
            Path binPath = FIXTURES_DIR.resolve(pn + ".bin");
            assertTrue(Files.isRegularFile(binPath), "Binary fixture must exist: " + binPath);

            byte[] bytes = Files.readAllBytes(binPath);

            Stm8PartRecord part = registry.getRequiredPart(pn);
            Stm8VectorTable table = Stm8VectorTableParser.parse(
                bytes, part, ParserLimits.defaults(), CancellationToken.none()
            );

            assertNotNull(table);
            assertEquals(0x008000L, table.baseAddress());
            assertEquals(32, table.entries().size());
            assertEquals(0x008080L, table.resetTargetAddress());

            // Score and confidence
            assertTrue(table.isConfident());
            assertTrue(table.score().resetVectorValid());
            assertEquals(32, table.score().validOpcodeCount());
            assertEquals(32, table.score().validTargetCount());
            assertEquals(Confidence.DERIVED, table.score().confidence());

            // Slot 0 (RESET)
            Optional<Stm8VectorEntry> resetEntry = table.entry(0);
            assertTrue(resetEntry.isPresent());
            assertEquals(Stm8VectorSlot.SLOT_0_RESET, resetEntry.get().slot());
            assertEquals(0x82, resetEntry.get().opcode());
            assertEquals(0x008080L, resetEntry.get().targetAddress());
            assertEquals("Reset_Handler", resetEntry.get().handlerLabel());
            assertTrue(resetEntry.get().isValid());
            assertFalse(resetEntry.get().isStub());

            // Slot 1 (TRAP)
            Optional<Stm8VectorEntry> trapEntry = table.entry(1);
            assertTrue(trapEntry.isPresent());
            assertEquals(Stm8VectorSlot.SLOT_1_TRAP, trapEntry.get().slot());
            assertEquals(0x82, trapEntry.get().opcode());
            assertEquals(0x008090L, trapEntry.get().targetAddress());
            assertEquals("TRAP_IRQHandler", trapEntry.get().handlerLabel());
            assertTrue(trapEntry.get().isValid());

            // Label lookup
            Optional<Stm8VectorEntry> byLabel = table.entryByLabel("Reset_Handler");
            assertTrue(byLabel.isPresent());
            assertEquals(0, byLabel.get().slot().slotIndex());
        }
    }

    @Test
    void discoverVectorTableLocatesOffsetCorrectly() throws IOException, DiagnosticException {
        Path binPath = FIXTURES_DIR.resolve("STM8S003F3P6.bin");
        byte[] bytes = Files.readAllBytes(binPath);
        Stm8PartRecord part = registry.getRequiredPart("STM8S003F3P6");

        // Discovered with flash base 0x008000
        Stm8VectorTable table = Stm8VectorTableParser.discover(
            bytes, 0x008000L, part, ParserLimits.defaults(), CancellationToken.none()
        );
        assertEquals(0x008080L, table.resetTargetAddress());
        assertTrue(table.isConfident());
    }

    @Test
    void failClosedOnTruncatedVectorTable() throws IOException {
        Path truncatedPath = MALFORMED_DIR.resolve("stm8s103_truncated.bin");
        assertTrue(Files.isRegularFile(truncatedPath));
        byte[] bytes = Files.readAllBytes(truncatedPath);
        assertEquals(64, bytes.length);

        DiagnosticException ex = assertThrows(
            DiagnosticException.class,
            () -> Stm8VectorTableParser.parse(bytes, null, ParserLimits.defaults(), CancellationToken.none())
        );
        assertEquals(DiagnosticCode.STM8_VECTOR_TABLE_TRUNCATED, ex.diagnostic().code());
    }

    @Test
    void failClosedOnInvalidResetVectorOpcode() throws IOException, DiagnosticException {
        Path invalidOpcodePath = MALFORMED_DIR.resolve("stm8af_invalid_opcode.bin");
        assertTrue(Files.isRegularFile(invalidOpcodePath));
        byte[] bytes = Files.readAllBytes(invalidOpcodePath);

        // Parsing without throw records UNKNOWN confidence
        Stm8VectorTable table = Stm8VectorTableParser.parse(
            bytes, null, ParserLimits.defaults(), CancellationToken.none()
        );
        assertFalse(table.isConfident());
        assertFalse(table.score().resetVectorValid());
        assertEquals(Confidence.UNKNOWN, table.score().confidence());

        // Strict parseAndValidate fails closed
        DiagnosticException ex = assertThrows(
            DiagnosticException.class,
            () -> Stm8VectorTableParser.parseAndValidate(
                bytes, 0, 0x008000L, null, ParserLimits.defaults(), CancellationToken.none()
            )
        );
        assertEquals(DiagnosticCode.STM8_VECTOR_TABLE_INVALID, ex.diagnostic().code());
    }

    @Test
    void failClosedOnOutOfBoundsResetVectorTarget() throws IOException, DiagnosticException {
        Path outOfBoundsPath = MALFORMED_DIR.resolve("stm8al_out_of_bounds_vector.bin");
        assertTrue(Files.isRegularFile(outOfBoundsPath));
        byte[] bytes = Files.readAllBytes(outOfBoundsPath);

        Stm8PartRecord part = registry.getRequiredPart("STM8AL3188TA"); // 64 KiB Flash: 0x008000 to 0x017FFF

        // Reset target 0x040000 is outside physical flash
        Stm8VectorTable table = Stm8VectorTableParser.parse(
            bytes, part, ParserLimits.defaults(), CancellationToken.none()
        );
        assertFalse(table.isConfident());
        assertFalse(table.score().resetVectorValid());
        assertEquals(Confidence.UNKNOWN, table.score().confidence());

        DiagnosticException ex = assertThrows(
            DiagnosticException.class,
            () -> Stm8VectorTableParser.parseAndValidate(
                bytes, 0, 0x008000L, part, ParserLimits.defaults(), CancellationToken.none()
            )
        );
        assertEquals(DiagnosticCode.STM8_VECTOR_TABLE_INVALID, ex.diagnostic().code());
    }

    @Test
    void cancellationTokenAbortsParsing() throws IOException {
        Path binPath = FIXTURES_DIR.resolve("STM8S003F3P6.bin");
        byte[] bytes = Files.readAllBytes(binPath);

        CancellationToken cancelledToken = () -> true;
        DiagnosticException ex = assertThrows(
            DiagnosticException.class,
            () -> Stm8VectorTableParser.parse(bytes, null, ParserLimits.defaults(), cancelledToken)
        );
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }

    @Test
    void vectorSlotHandlerLabelsDistinguishFamilies() {
        Stm8VectorSlot slot10 = Stm8VectorSlot.SLOT_10_CAN_RX_OR_AES_OR_TOUCH;
        assertEquals("CAN_RX_IRQHandler", slot10.handlerLabelForFamily("STM8S"));
        assertEquals("AES_IRQHandler", slot10.handlerLabelForFamily("STM8L"));
        assertEquals("CAN_RX_IRQHandler", slot10.handlerLabelForFamily("STM8AF"));
        assertEquals("AES_IRQHandler", slot10.handlerLabelForFamily("STM8AL"));
        assertEquals("TOUCH_IRQHandler", slot10.handlerLabelForFamily("STM8T"));

        Stm8VectorSlot slot13 = Stm8VectorSlot.SLOT_13_TIM1_UPD_OR_RTC;
        assertEquals("TIM1_UPD_OVF_TRG_BRK_IRQHandler", slot13.handlerLabelForFamily("STM8S"));
        assertEquals("RTC_IRQHandler", slot13.handlerLabelForFamily("STM8L"));
    }
}
