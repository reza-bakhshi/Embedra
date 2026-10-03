package io.github.rezabakhshi.embedra.targets.rp.pio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class RpPioScannerTest {

    @Test
    void testDiscoverProgramViaStructure() throws Exception {
        // Lay out memory:
        // 0x10000100: 3 PIO instructions (set pins 1, set pins 0, jmp 0) = 6 bytes
        // 0x10000120: pio_program_t { uint32_t ptr = 0x10000100, uint8_t len = 3, int8_t origin = -1 }
        byte[] data = new byte[256];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // Instructions at offset 0x00 (mapped to 0x10000100)
        buf.putShort(0x00, (short) 0xE001); // SET pins, 1
        buf.putShort(0x02, (short) 0xE000); // SET pins, 0
        buf.putShort(0x04, (short) 0x0000); // JMP 0

        // pio_program_t struct at offset 0x20
        buf.putInt(0x20, 0x10000100);       // pointer
        data[0x24] = 3;                      // length
        data[0x25] = (byte) -1;              // origin (-1 = relocatable)

        RpUf2Segment seg = new RpUf2Segment(0x10000100L, data, Optional.empty());
        List<RpPioProgram> programs =
                RpPioScanner.scan(List.of(seg), ParserLimits.defaults(), CancellationToken.none());

        assertEquals(1, programs.size());
        RpPioProgram prog = programs.get(0);
        assertEquals(0x10000100L, prog.address());
        assertTrue(prog.structureAddress().isPresent());
        assertEquals(0x10000120L, prog.structureAddress().getAsLong());
        assertEquals(3, prog.length());
        assertEquals(-1, prog.origin());
        assertTrue(prog.isRelocatable());
        assertEquals(3, prog.instructions().size());
        assertEquals("set pins, 1", prog.instructions().get(0).toAssemblyString());
        assertEquals("set pins, 0", prog.instructions().get(1).toAssemblyString());
        assertEquals("jmp 0", prog.instructions().get(2).toAssemblyString());
    }

    @Test
    void testDiscoverProgramViaHeuristicScan() throws Exception {
        // Lay out memory without struct pointer:
        // 0x10000200: standalone PIO loop (set pindirs 31, out pins 8, jmp 0)
        byte[] data = new byte[128];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        buf.putShort(0x10, (short) 0xE085); // SET pindirs, 5
        buf.putShort(0x12, (short) 0x6008); // OUT pins, 8
        buf.putShort(0x14, (short) 0x0000); // JMP 0

        RpUf2Segment seg = new RpUf2Segment(0x10000200L, data, Optional.empty());
        List<RpPioProgram> programs =
                RpPioScanner.scan(List.of(seg), ParserLimits.defaults(), CancellationToken.none());

        assertFalse(programs.isEmpty());
        RpPioProgram prog = programs.get(0);
        assertEquals(0x10000210L, prog.address());
        assertFalse(prog.structureAddress().isPresent());
        assertEquals(3, prog.length());
        assertEquals("set pindirs, 5", prog.instructions().get(0).toAssemblyString());
        assertEquals("out pins, 8", prog.instructions().get(1).toAssemblyString());
        assertEquals("jmp 0", prog.instructions().get(2).toAssemblyString());
    }

    @Test
    void testCancellation() {
        byte[] data = new byte[64];
        RpUf2Segment seg = new RpUf2Segment(0x10000000L, data, Optional.empty());
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpPioScanner.scan(List.of(seg), ParserLimits.defaults(), () -> true));
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }

    @Test
    void testParserLimitsExceeded() {
        byte[] data = new byte[256];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        // Put 5 pio_program_t structures
        for (int i = 0; i < 5; i++) {
            buf.putShort(i * 8, (short) 0xE001);
            buf.putShort(i * 8 + 2, (short) 0x0000);
            buf.putInt(0x40 + (i * 8), 0x10000000 + (i * 8));
            data[0x40 + (i * 8) + 4] = 2;
            data[0x40 + (i * 8) + 5] = -1;
        }

        RpUf2Segment seg = new RpUf2Segment(0x10000000L, data, Optional.empty());
        ParserLimits limits = new ParserLimits(10000, 10000, 10000, 2, 10, Duration.ofSeconds(1));
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpPioScanner.scan(List.of(seg), limits, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void testScanBlinky() throws Exception {
        java.nio.file.Path path = java.nio.file.Path.of("src/test/resources/fixtures/rp/rp2040-pico-blinky.uf2");
        io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Image image =
                io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Parser.parse(
                        path, ParserLimits.defaults(), CancellationToken.none());
        List<RpPioProgram> programs =
                RpPioScanner.scan(image.segments(), ParserLimits.defaults(), CancellationToken.none());
        assertTrue(programs.stream().anyMatch(p -> p.address() == 0x10000190L && p.length() == 3),
                "Should discover 3-instruction PIO program at 0x10000190");
    }
}
