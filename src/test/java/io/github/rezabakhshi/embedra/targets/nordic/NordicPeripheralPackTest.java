package io.github.rezabakhshi.embedra.targets.nordic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicCatalogRegistry;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicBitField;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicCryptoCellDefinition;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicDefaultPacks;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicDevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicEasyDmaType;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicEasyDmaValidator;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicPeripheral;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicPeripheralPack;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicPeripheralPackLoader;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicPeripheralSchemaTransform;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicRegister;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Comprehensive automated tests for Nordic SVD / MDK peripheral register packs,
 * EasyDMA schemas, and CryptoCell hardware definitions (T100).
 */
class NordicPeripheralPackTest {

    @Test
    void testBitFieldValidationAndCalculations() {
        NordicBitField bf = new NordicBitField("FIELD", 2, 4, 0x3CL, "R/W", "Test field");
        assertEquals("FIELD", bf.name());
        assertEquals(2, bf.bitOffset());
        assertEquals(4, bf.bitWidth());
        assertEquals(0x3CL, bf.mask());
        assertEquals("R/W", bf.access());
        assertEquals("Test field", bf.description());

        NordicBitField single = NordicBitField.singleBit("FLAG", 7, "R", "Single bit flag");
        assertEquals(0x80L, single.mask());

        // Boundary violations
        assertThrows(IllegalArgumentException.class, () ->
            new NordicBitField("", 0, 1, 1L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new NordicBitField("BAD_OFFSET", -1, 1, 1L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new NordicBitField("BAD_OFFSET", 32, 1, 1L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new NordicBitField("BAD_WIDTH", 0, 0, 0L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new NordicBitField("OVERFLOW", 30, 4, 0xF0000000L, "R", ""));
        assertThrows(IllegalArgumentException.class, () ->
            new NordicBitField("WRONG_MASK", 0, 2, 0x07L, "R", ""));
    }

    @Test
    void testRegisterAlignmentAndApertureEnforcement() {
        // Valid non-secure MMIO register
        NordicRegister r1 = new NordicRegister("VALID_NS", 0x40001000L, 0x000L, 32, "Valid", List.of());
        assertEquals(0x40001000L, r1.address());
        assertEquals(0x000L, r1.offset());
        assertEquals(32, r1.widthBits());

        // Valid secure MMIO register
        NordicRegister r2 = new NordicRegister("VALID_SEC", 0x50003000L, 0x000L, 32, "Valid Secure", List.of());
        assertEquals(0x50003000L, r2.address());

        // Unaligned address
        assertThrows(IllegalArgumentException.class, () ->
            new NordicRegister("UNALIGNED_ADDR", 0x40001001L, 0x000L, 32, "Bad", List.of()));
        // Unaligned offset
        assertThrows(IllegalArgumentException.class, () ->
            new NordicRegister("UNALIGNED_OFF", 0x40001004L, 0x002L, 32, "Bad", List.of()));

        // Out of MMIO bounds: e.g. Flash (0x00001000) or SRAM (0x20000000)
        assertThrows(IllegalArgumentException.class, () ->
            new NordicRegister("IN_FLASH", 0x00001000L, 0x000L, 32, "Bad", List.of()));
        assertThrows(IllegalArgumentException.class, () ->
            new NordicRegister("IN_SRAM", 0x20000000L, 0x000L, 32, "Bad", List.of()));
        assertThrows(IllegalArgumentException.class, () ->
            new NordicRegister("IN_SYSTEM", 0xE000E000L, 0x000L, 32, "Bad", List.of()));

        // Bitfield overlap detection
        NordicBitField bf1 = new NordicBitField("B1", 0, 4, 0x0FL, "R/W", "B1");
        NordicBitField bf2 = new NordicBitField("B2", 3, 2, 0x18L, "R/W", "B2 overlaps B1 at bit 3");
        assertThrows(IllegalArgumentException.class, () ->
            new NordicRegister("COLLISION", 0x40001000L, 0x000L, 32, "Collision", List.of(bf1, bf2)));
    }

    @Test
    void testEasyDmaMemoryApertureAndPointerValidation() {
        // Valid pointer in internal SRAM (32-bit aligned)
        assertTrue(NordicEasyDmaValidator.isValidPointerTarget(0x20000000L, false));
        assertTrue(NordicEasyDmaValidator.isValidPointerTarget(0x20004000L, false));
        assertTrue(NordicEasyDmaValidator.isValidPointerTarget(0x2001FFFCL, false));

        // Read-only TX pointers in Flash and QSPI
        assertTrue(NordicEasyDmaValidator.isValidPointerTarget(0x00010000L, true));
        assertTrue(NordicEasyDmaValidator.isValidPointerTarget(0x12000000L, true));

        // Write DMA cannot target Flash
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x00010000L, false));
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x12000000L, false));

        // Rejection of unaligned pointers
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x20000001L, false));
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x20000002L, false));
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x20000003L, false));

        // Rejection of MMIO apertures
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x40000000L, true));
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x50000000L, true));
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x5002A000L, true));

        // Rejection of FICR / UICR configuration regions
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x10000000L, true));
        assertFalse(NordicEasyDmaValidator.isValidPointerTarget(0x10001014L, true));

        // Validation methods throw appropriate exceptions
        assertThrows(IllegalArgumentException.class, () ->
            NordicEasyDmaValidator.validatePointerTarget(0x20000002L, false));
        assertThrows(IllegalArgumentException.class, () ->
            NordicEasyDmaValidator.validatePointerTarget(0x40001000L, false));
        assertThrows(IllegalArgumentException.class, () ->
            NordicEasyDmaValidator.validatePointerTarget(0x10001000L, false));

        // Buffer count validation
        NordicEasyDmaValidator.validateBufferCount(1024, 2048);
        assertThrows(IllegalArgumentException.class, () ->
            NordicEasyDmaValidator.validateBufferCount(-1, 2048));
        assertThrows(IllegalArgumentException.class, () ->
            NordicEasyDmaValidator.validateBufferCount(4096, 2048));

        // List mode validation
        NordicEasyDmaValidator.validateListMode(0);
        NordicEasyDmaValidator.validateListMode(1);
        assertThrows(IllegalArgumentException.class, () -> NordicEasyDmaValidator.validateListMode(2));
    }

    @Test
    void testHardwareCryptoCellCc310AndCc312Definitions() {
        // CC310 on nRF52840 at 0x5002A000
        NordicPeripheral cc310 = NordicCryptoCellDefinition.createCc310Peripheral();
        assertEquals("CRYPTOCELL_CC310", cc310.name());
        assertEquals(0x5002A000L, cc310.baseAddress());
        assertEquals(0x5002B000L, cc310.endExclusive());
        assertTrue(cc310.registers().size() >= 25);
        assertTrue(cc310.findRegisterByName("AES_CONTROL").isPresent());
        assertTrue(cc310.findRegisterByName("HOST_CRYPTOKEY_SEL").isPresent());
        assertTrue(cc310.findRegisterByName("PKA_CONTROL").isPresent());
        assertTrue(cc310.findRegisterByName("TRNG_CONTROL").isPresent());

        // CC312 on nRF5340 / nRF9160 at 0x50840000
        NordicPeripheral cc312 = NordicCryptoCellDefinition.createCc312Peripheral();
        assertEquals("CRYPTOCELL_CC312", cc312.name());
        assertEquals(0x50840000L, cc312.baseAddress());
        assertEquals(0x50841000L, cc312.endExclusive());
        assertTrue(cc312.registers().size() >= 25);
        assertTrue(cc312.findRegisterByName("AES_CONTROL").isPresent());
        assertTrue(cc312.findRegisterByName("AES_BUSY").isPresent());
        assertTrue(cc312.findRegisterByName("HASH_CONTROL").isPresent());
        assertTrue(cc312.findRegisterByName("PKA_CONTROL").isPresent());
    }

    @Test
    void testSpuAndDppiTrustZoneDefinitions() {
        NordicPeripheral spu = NordicDefaultPacks.createSpuPeripheral(0x50003000L, "SPU");
        assertEquals("SPU", spu.name());
        assertEquals(0x50003000L, spu.baseAddress());
        assertTrue(spu.findRegisterByName("FLASHNSC0_REGION").isPresent());
        assertTrue(spu.findRegisterByName("FLASHREGION_0_PERM").isPresent());
        assertTrue(spu.findRegisterByName("RAMREGION_0_PERM").isPresent());
        assertTrue(spu.findRegisterByName("PERIPHID_0_PERM").isPresent());
        assertTrue(spu.findRegisterByName("CAPABILITIES").isPresent());

        NordicPeripheral dppi = NordicDefaultPacks.createDppiPeripheral(0x50025000L, "DPPI_SECURE");
        assertEquals("DPPI_SECURE", dppi.name());
        assertEquals(0x50025000L, dppi.baseAddress());
        assertTrue(dppi.findRegisterByName("CHEN").isPresent());
        assertTrue(dppi.findRegisterByName("CHENSET").isPresent());
        assertTrue(dppi.findRegisterByName("CHG_0").isPresent());
    }

    @Test
    void testPeripheralPackIntegrityAcrossAllFiveSeries() throws DiagnosticException {
        NordicDevicePackRegistry registry = NordicDevicePackRegistry.loadDefault();
        assertTrue(registry.packCount() >= 5);

        for (String series : List.of("nRF51", "nRF52", "nRF53", "nRF54", "nRF91")) {
            NordicPeripheralPack pack = registry.getRequiredPack(series);
            assertNotNull(pack);
            assertEquals(series, pack.series());
            assertTrue(pack.peripherals().size() >= 10, series + " must have at least 10 peripherals");
            assertTrue(pack.totalRegisterCount() >= 50, series + " must have at least 50 registers");

            // Validate that every peripheral is strictly within MMIO aperture
            for (NordicPeripheral p : pack.peripherals()) {
                assertTrue(
                    (p.baseAddress() >= 0x40000000L && p.endExclusive() <= 0x50000000L) ||
                    (p.baseAddress() >= 0x50000000L && p.endExclusive() <= 0x60000000L),
                    "Peripheral " + p.name() + " in " + series + " must reside in MMIO aperture"
                );
            }
        }

        // Check catalog part integration
        NordicCatalogRegistry catalog = NordicCatalogRegistry.loadDefault();
        NordicPartRecord nrf52840 = catalog.findExactPart("nRF52840-QIAA").orElseThrow();
        NordicPeripheralPack nrf52Pack = registry.getRequiredPack(nrf52840);
        assertTrue(nrf52Pack.findPeripheral("CRYPTOCELL_CC310").isPresent());

        NordicPartRecord nrf5340 = catalog.findExactPart("nRF5340-QKAA").orElseThrow();
        NordicPeripheralPack nrf53Pack = registry.getRequiredPack(nrf5340);
        assertTrue(nrf53Pack.findPeripheral("CRYPTOCELL_CC312").isPresent());
        assertTrue(nrf53Pack.findPeripheral("SPU").isPresent());
        assertTrue(nrf53Pack.findPeripheral("DPPI_SECURE").isPresent());
    }

    @Test
    void testEasyDmaRegistersInPacks() throws DiagnosticException {
        NordicDevicePackRegistry registry = NordicDevicePackRegistry.loadDefault();
        NordicPeripheralPack nrf52Pack = registry.getRequiredPack("nRF52");

        List<NordicRegister> easyDmaRegs = nrf52Pack.easyDmaRegisters();
        assertFalse(easyDmaRegs.isEmpty());
        assertTrue(easyDmaRegs.stream().anyMatch(r -> r.easyDmaType() == NordicEasyDmaType.PTR));
        assertTrue(easyDmaRegs.stream().anyMatch(r -> r.easyDmaType() == NordicEasyDmaType.MAXCNT));
        assertTrue(easyDmaRegs.stream().anyMatch(r -> r.easyDmaType() == NordicEasyDmaType.AMOUNT));
        assertTrue(easyDmaRegs.stream().anyMatch(r -> r.easyDmaType() == NordicEasyDmaType.LIST));
    }

    @Test
    void testPackLoaderBoundedLimitsAndCancellation(@TempDir Path tempDir) throws Exception {
        Path validJson = tempDir.resolve("test-peripherals.json");
        String content = """
            {
              "schemaId": "urn:embedra:schema:nordic-peripheral-pack:1",
              "packId": "test-pack",
              "series": "nRF52",
              "sourceReference": "Test",
              "peripherals": [
                {
                  "name": "TEST_UART",
                  "baseAddress": "0x40002000",
                  "endExclusive": "0x40003000",
                  "description": "Test UART",
                  "registers": [
                    {
                      "name": "TEST_REG",
                      "address": "0x40002000",
                      "offset": "0x0000",
                      "widthBits": 32,
                      "description": "Test Reg",
                      "bitfields": []
                    }
                  ]
                }
              ]
            }
            """;
        Files.writeString(validJson, content, StandardCharsets.UTF_8);

        // Success load
        NordicPeripheralPack pack = NordicPeripheralPackLoader.load(
            validJson, null, ParserLimits.defaults(), CancellationToken.none());
        assertEquals("test-pack", pack.packId());
        assertEquals("nRF52", pack.series());

        // Cancelled token
        CancellationToken cancelled = () -> true;
        assertThrows(DiagnosticException.class, () ->
            NordicPeripheralPackLoader.load(validJson, null, ParserLimits.defaults(), cancelled));

        // Limit exceeded
        ParserLimits lowLimits = ParserLimits.defaults().withMaxAllocationBytes(10);
        assertThrows(DiagnosticException.class, () ->
            NordicPeripheralPackLoader.load(validJson, null, lowLimits, CancellationToken.none()));

        // Checksum mismatch
        Path badSha = tempDir.resolve("test-peripherals.sha256");
        String badHashLine = "0000000000000000000000000000000000000000000000000000000000000000"
            + "  test-peripherals.json";
        Files.writeString(badSha, badHashLine);
        DiagnosticException de = assertThrows(DiagnosticException.class, () ->
            NordicPeripheralPackLoader.load(validJson, badSha, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.NORDIC_PACK_INTEGRITY_MISMATCH, de.diagnostic().code());
    }

    @Test
    void testSchemaTransformComments() {
        NordicRegister reg = new NordicRegister(
            "UARTE_RXD_PTR", 0x40002534L, 0x534L, 32, "Data pointer for RX buffer",
            List.of(), true, NordicEasyDmaType.PTR
        );
        String regComment = NordicPeripheralSchemaTransform.formatRegisterComment(reg);
        assertTrue(regComment.contains("[UARTE_RXD_PTR] (0x40002534, 32-bit)"));
        assertTrue(regComment.contains("[EasyDMA: PTR]"));

        NordicPeripheral periph = new NordicPeripheral(
            "UARTE0", 0x40002000L, 0x40003000L, "Universal Asynchronous Receiver/Transmitter", List.of(reg)
        );
        String plateComment = NordicPeripheralSchemaTransform.formatPeripheralPlateComment(periph);
        assertTrue(plateComment.contains("=== Nordic nRF UARTE0 Peripheral Block ==="));
        assertTrue(plateComment.contains("Base: 0x40002000 - 0x40002FFF"));
        assertTrue(plateComment.contains("Registers: 1"));
    }
}
