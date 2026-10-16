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
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelBitField;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelDevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelFuseBit;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelFuseByte;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelFuseMap;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelFusePolarity;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelInterrupt;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelIoPort;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelPeripheral;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelPeripheralPack;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelPeripheralPackLoader;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelPeripheralSchemaTransform;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelRegister;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit test suite verifying Atmel/Microchip peripheral register packs, I/O ports,
 * fuse bit maps, and schema transforms (T108).
 */
class AtmelPeripheralPackTest {

    @Test
    void testBitFieldValidationAndCalculations() {
        AtmelBitField bf = new AtmelBitField("FIELD", 2, 4, 0x3CL, "R/W", "Test field");
        assertEquals("FIELD", bf.name());
        assertEquals(2, bf.bitOffset());
        assertEquals(4, bf.bitWidth());
        assertEquals(0x3CL, bf.mask());
        assertEquals("R/W", bf.access());
        assertEquals("Test field", bf.description());

        AtmelBitField single = AtmelBitField.singleBit("FLAG", 7, "R", "Single bit flag");
        assertEquals(0x80L, single.mask());

        assertThrows(IllegalArgumentException.class, () ->
            new AtmelBitField("", 0, 1, 1L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelBitField("BAD_OFFSET", -1, 1, 1L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelBitField("BAD_OFFSET", 32, 1, 1L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelBitField("BAD_WIDTH", 0, 0, 1L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelBitField("BAD_WIDTH", 0, 33, 1L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelBitField("EXCEEDS", 30, 4, 0xF0000000L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelBitField("BAD_MASK", 0, 1, 0L, "R", ""));
    }

    @Test
    void testRegisterValidation() {
        AtmelBitField bf = AtmelBitField.singleBit("EN", 0, "R/W", "Enable bit");
        AtmelRegister reg = new AtmelRegister(
            "CTRLA", 0x4000L, 0x00L, 8, "R/W", "Control A", List.of(bf));
        assertEquals("CTRLA", reg.name());
        assertEquals(0x4000L, reg.address());
        assertEquals(0x00L, reg.offset());
        assertEquals(8, reg.widthBits());
        assertEquals("R/W", reg.access());
        assertEquals(0x4000L, reg.effectiveAddress(0x4000L));
        assertEquals(0x4010L, new AtmelRegister("SUB", 0x10L, 0x10L, 8, "R/W", "", List.of())
            .effectiveAddress(0x4000L));

        assertTrue(reg.findBitFieldByName("EN").isPresent());
        assertFalse(reg.findBitFieldByName("NONEXISTENT").isPresent());

        assertThrows(IllegalArgumentException.class, () ->
            new AtmelRegister("", 0x10L, 0L, 8, "R/W", "", List.of()));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelRegister("BAD_ADDR", -1L, 0L, 8, "R/W", "", List.of()));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelRegister("BAD_WIDTH", 0x10L, 0L, 12, "R/W", "", List.of()));
    }

    @Test
    void testPeripheralValidation() {
        AtmelRegister r1 = new AtmelRegister("R1", 0x20L, 0x20L, 8, "R/W", "Reg 1", List.of());
        AtmelRegister r2 = new AtmelRegister("R2", 0x21L, 0x21L, 8, "R/W", "Reg 2", List.of());
        AtmelPeripheral periph = new AtmelPeripheral(
            "PORTB", 0x20L, 0x23L, "DATA", "Port B registers", List.of(r1, r2));

        assertEquals("PORTB", periph.name());
        assertEquals(0x20L, periph.baseAddress());
        assertEquals(0x23L, periph.endExclusive());
        assertEquals(0x23L, periph.effectiveEndAddress());
        assertEquals(2, periph.registers().size());

        assertTrue(periph.findFirstRegisterByName("R1").isPresent());
        assertEquals(1, periph.findRegistersByName("R2").size());
        assertTrue(periph.findFirstRegisterByAddress(0x20L).isPresent());
        assertEquals(1, periph.findRegistersByAddress(0x21L).size());

        // Out of bounds register
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelPeripheral("BAD", 0x20L, 0x22L, "DATA", "", List.of(
                new AtmelRegister("OUT", 0x25L, 0x25L, 8, "R/W", "", List.of()))));
    }

    @Test
    void testIoPortValidation() {
        AtmelIoPort port = new AtmelIoPort("PORTB", 8, "PORTB", "DDRB", "PINB");
        assertEquals("PORTB", port.name());
        assertEquals(8, port.pinCount());
        assertEquals("PORTB", port.dataRegister());
        assertEquals("DDRB", port.directionRegister());
        assertEquals("PINB", port.inputRegister());

        assertThrows(IllegalArgumentException.class, () ->
            new AtmelIoPort("", 8, "P", "D", "I"));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelIoPort("PORT", 0, "P", "D", "I"));
        assertThrows(IllegalArgumentException.class, () ->
            new AtmelIoPort("PORT", 65, "P", "D", "I"));
    }

    @Test
    void testFuseValidation() {
        AtmelFuseBit bod = new AtmelFuseBit(
            "BODLEVEL", 0, 3, 7L, AtmelFusePolarity.PROGRAMMED_LOW, "BOD level");
        AtmelFuseBit spien = new AtmelFuseBit(
            "SPIEN", 5, 1, 32L, AtmelFusePolarity.PROGRAMMED_LOW, "SPI programming enable");

        // SPIEN bit (bit 5): 0 = programmed, 1 = unprogrammed
        assertTrue(spien.isProgrammed(0xDF));  // bit 5 is 0 -> programmed
        assertFalse(spien.isProgrammed(0xFF)); // bit 5 is 1 -> unprogrammed

        AtmelFuseByte highByte = new AtmelFuseByte("HIGH", 1, 8, 0xD9, "High fuse byte", List.of(spien));
        assertEquals("HIGH", highByte.name());
        assertEquals(1, highByte.address());
        assertEquals(8, highByte.sizeBits());
        assertEquals(0xD9, highByte.defaultValue());
        assertTrue(highByte.findBitByName("SPIEN").isPresent());

        AtmelFuseMap map = new AtmelFuseMap("PINNED", null, List.of(highByte));
        assertTrue(map.isPinned());
        assertTrue(map.isAvailable());
        assertTrue(map.findByteByName("HIGH").isPresent());
        assertTrue(map.findByteByAddress(1).isPresent());
    }

    @Test
    void testSchemaTransforms() {
        AtmelBitField bf = new AtmelBitField("CS0", 0, 3, 7L, "R/W", "Clock select");
        AtmelRegister reg = new AtmelRegister("TCCR0B", 0x45L, 0x45L, 8, "R/W", "Timer control", List.of(bf));
        String regComment = AtmelPeripheralSchemaTransform.formatRegisterComment(reg);
        assertTrue(regComment.contains("[TCCR0B] (0x45, 8-bit)"));
        assertTrue(regComment.contains("[2:0] CS0 (R/W, 0x7)"));

        AtmelPeripheral periph = new AtmelPeripheral("TC0", 0x40L, 0x50L, "DATA", "8-bit Timer", List.of(reg));
        String plateComment = AtmelPeripheralSchemaTransform.formatPeripheralPlateComment(periph);
        assertTrue(plateComment.contains("=== Atmel TC0 Peripheral Block ==="));
        assertTrue(plateComment.contains("Base: 0x40 - 0x4F"));

        AtmelIoPort port = new AtmelIoPort("PORTB", 8, "PORTB", "DDRB", "PINB");
        String ioComment = AtmelPeripheralSchemaTransform.formatIoPortComment(port);
        assertTrue(ioComment.contains("=== I/O Port PORTB (8-pin) ==="));

        AtmelFuseBit bit = new AtmelFuseBit("DWEN", 3, 1, 8L, AtmelFusePolarity.PROGRAMMED_LOW, "DebugWIRE");
        AtmelFuseByte fByte = new AtmelFuseByte("HIGH", 1, 8, 0xD9, "High fuse", List.of(bit));
        String fuseComment = AtmelPeripheralSchemaTransform.formatFuseByteComment(fByte, 0xD9);
        assertTrue(fuseComment.contains("=== Fuse HIGH (0x01) ==="));
        assertTrue(fuseComment.contains("DWEN"));

        List<AtmelInterrupt> interrupts = List.of(
            new AtmelInterrupt(0, "RESET", "Reset vector"),
            new AtmelInterrupt(1, "INT0", "External interrupt 0")
        );
        String intrComment = AtmelPeripheralSchemaTransform.formatInterruptPlateComment(interrupts);
        assertTrue(intrComment.contains("=== Interrupt Vector Table ==="));
        assertTrue(intrComment.contains("[ 0] RESET"));
        assertTrue(intrComment.contains("[ 1] INT0"));
    }

    @Test
    void testDefaultRegistryLoadsAllPacks() throws DiagnosticException {
        AtmelDevicePackRegistry registry = AtmelDevicePackRegistry.loadDefault();
        assertEquals(24, registry.packCount(), "Registry must contain all 24 curated packs");

        // Verify representative parts
        String[] representative = {
            "ATmega328P", "ATmega2560", "ATmega32U4", "ATtiny85",
            "AVR128DA48", "SAMD21G18A", "SAME70Q21", "SAM3X8E"
        };
        for (String part : representative) {
            Optional<AtmelPeripheralPack> pack = registry.packForPart(part);
            assertTrue(pack.isPresent(), "Pack must be present for " + part);
            assertEquals(part, pack.get().catalogPart());
            assertFalse(pack.get().peripherals().isEmpty(), "Peripherals must not be empty for " + part);
            assertTrue(pack.get().registerCount() > 0, "Register count must be > 0 for " + part);
            assertTrue(pack.get().bitfieldCount() > 0, "Bitfield count must be > 0 for " + part);
        }

        // Verify ATmega328P details
        AtmelPeripheralPack mega328p = registry.packForPart("ATmega328P").orElseThrow();
        assertEquals("ATmega", mega328p.series());
        assertEquals("DATA", mega328p.addressSpace());
        assertEquals(3, mega328p.ioPorts().size());
        assertTrue(mega328p.fuseMap().isPinned());
        assertEquals(4, mega328p.fuseMap().bytes().size());
        assertEquals(26, mega328p.interrupts().size());

        // Verify SAMD21G18A details
        AtmelPeripheralPack samd21 = registry.packForPart("SAMD21G18A").orElseThrow();
        assertEquals("SAMD", samd21.series());
        assertEquals("PERIPHERAL", samd21.addressSpace());
        assertTrue(samd21.findPeripheralByName("PORT").isPresent());
        assertTrue(samd21.findPeripheralByName("SYSCTRL").isPresent());

        // Verify device alias lookup
        assertTrue(registry.packForDevice("ATSAMD21G18A").isPresent());
    }

    @Test
    void testPackLoaderLimitsAndCancellation(@TempDir Path tempDir) throws Exception {
        Path validPack = AtmelDevicePackRegistry.DEFAULT_PACKS_DIR.resolve("atmega328p-peripherals.json");
        Path validSha = AtmelDevicePackRegistry.DEFAULT_PACKS_DIR.resolve("atmega328p-peripherals.sha256");

        // Limits exceeded
        ParserLimits tinyLimits = ParserLimits.defaults().withMaxAllocationBytes(10);
        DiagnosticException limEx = assertThrows(DiagnosticException.class, () ->
            AtmelPeripheralPackLoader.load(validPack, validSha, tinyLimits, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limEx.diagnostic().code());

        // Cancellation
        CancellationToken cancelled = () -> true;
        DiagnosticException cancelEx = assertThrows(DiagnosticException.class, () ->
            AtmelPeripheralPackLoader.load(validPack, validSha, ParserLimits.defaults(), cancelled));
        assertEquals(DiagnosticCode.CANCELLED, cancelEx.diagnostic().code());

        // Checksum mismatch
        Path badSha = tempDir.resolve("bad.sha256");
        Files.writeString(badSha, "0000000000000000000000000000000000000000000000000000000000000000  bad.json\n");
        DiagnosticException shaEx = assertThrows(DiagnosticException.class, () ->
            AtmelPeripheralPackLoader.load(validPack, badSha, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.ATMEL_PACK_INTEGRITY_MISMATCH, shaEx.diagnostic().code());

        // Malformed JSON
        Path badJson = tempDir.resolve("bad.json");
        Files.writeString(badJson, "{ malformed json ");
        DiagnosticException badEx = assertThrows(DiagnosticException.class, () ->
            AtmelPeripheralPackLoader.load(badJson, null, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.ATMEL_PACK_INVALID, badEx.diagnostic().code());

        // Unsupported schema
        Path badSchema = tempDir.resolve("bad_schema.json");
        Files.writeString(badSchema, "{\"schemaId\":\"invalid:schema\"}");
        DiagnosticException schemaEx = assertThrows(DiagnosticException.class, () ->
            AtmelPeripheralPackLoader.load(badSchema, null, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.ATMEL_PACK_INVALID, schemaEx.diagnostic().code());
    }
}
