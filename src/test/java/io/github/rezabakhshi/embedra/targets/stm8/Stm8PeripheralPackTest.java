package io.github.rezabakhshi.embedra.targets.stm8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8CatalogRegistry;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8BitField;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8DevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8Peripheral;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8PeripheralPack;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8PeripheralPackLoader;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8PeripheralSchemaTransform;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8Register;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit test suite verifying STM8 peripheral pack definitions, bitfield semantics,
 * and schema transforms (T092).
 */
class Stm8PeripheralPackTest {

    private Stm8DevicePackRegistry packRegistry;

    private Stm8CatalogRegistry catalogRegistry;

    @BeforeEach
    void setUp() throws DiagnosticException {
        packRegistry = Stm8DevicePackRegistry.loadDefault();
        catalogRegistry = Stm8CatalogRegistry.loadDefault();
    }

    @Test
    void packsExistAndLoadForAllThreeMajorFamilies() {
        assertEquals(3, packRegistry.packCount(), "Pack registry must contain STM8S, STM8L, and STM8A");

        Optional<Stm8PeripheralPack> stm8sPack = packRegistry.packForFamily("STM8S");
        assertTrue(stm8sPack.isPresent(), "STM8S pack must be present");
        assertEquals("STM8S", stm8sPack.get().family());
        assertFalse(stm8sPack.get().peripherals().isEmpty(), "STM8S peripherals must not be empty");

        Optional<Stm8PeripheralPack> stm8lPack = packRegistry.packForFamily("STM8L");
        assertTrue(stm8lPack.isPresent(), "STM8L pack must be present");
        assertEquals("STM8L", stm8lPack.get().family());
        assertFalse(stm8lPack.get().peripherals().isEmpty(), "STM8L peripherals must not be empty");

        Optional<Stm8PeripheralPack> stm8aPack = packRegistry.packForFamily("STM8A");
        assertTrue(stm8aPack.isPresent(), "STM8A pack must be present");
        assertEquals("STM8A", stm8aPack.get().family());
        assertFalse(stm8aPack.get().peripherals().isEmpty(), "STM8A peripherals must not be empty");
    }

    @Test
    void packResolvesCorrectlyForCatalogParts() {
        Stm8PartRecord sPart = catalogRegistry.findPart("STM8S003F3P6").orElseThrow();
        Optional<Stm8PeripheralPack> sPack = packRegistry.packForPart(sPart);
        assertTrue(sPack.isPresent());
        assertEquals("STM8S", sPack.get().family());

        Stm8PartRecord lPart = catalogRegistry.findPart("STM8L151C8T6").orElseThrow();
        Optional<Stm8PeripheralPack> lPack = packRegistry.packForPart(lPart);
        assertTrue(lPack.isPresent());
        assertEquals("STM8L", lPack.get().family());

        Stm8PartRecord aPart = catalogRegistry.findPart("STM8AF5288TAY").orElseThrow();
        Optional<Stm8PeripheralPack> aPack = packRegistry.packForPart(aPart);
        assertTrue(aPack.isPresent());
        assertEquals("STM8A", aPack.get().family());
    }

    @Test
    void peripheralRegistersAndBitfieldsConformToByteWideSemantics() {
        for (String family : List.of("STM8S", "STM8L", "STM8A")) {
            Stm8PeripheralPack pack = packRegistry.packForFamily(family).orElseThrow();
            for (Stm8Peripheral peripheral : pack.peripherals()) {
                assertTrue(peripheral.baseAddress() >= 0x005000L && peripheral.endExclusive() <= 0x005800L,
                    "Peripheral " + peripheral.name() + " must reside in STM8 MMIO space [0x5000, 0x5800)");

                for (Stm8Register reg : peripheral.registers()) {
                    assertEquals(8, reg.widthBits(), "STM8 register width must be 8 bits (STM8-008)");
                    assertTrue(reg.address() >= peripheral.baseAddress()
                        && reg.address() < peripheral.endExclusive(),
                        "Register " + reg.name() + " must reside within its peripheral block");

                    for (Stm8BitField bf : reg.bitfields()) {
                        assertTrue(bf.bitOffset() >= 0 && bf.bitOffset() < 8, "Bit offset must be within [0, 7]");
                        assertTrue(bf.bitWidth() >= 1 && bf.bitWidth() <= 8, "Bit width must be within [1, 8]");
                        assertTrue(bf.bitOffset() + bf.bitWidth() <= 8,
                            "Bitfield must not exceed 8-bit register boundary");

                        int expectedMask = ((1 << bf.bitWidth()) - 1) << bf.bitOffset();
                        assertEquals(expectedMask, bf.mask(), "Bitfield mask must match width and offset");
                    }
                }
            }
        }
    }

    @Test
    void schemaTransformProducesStandardPlateAndEolComments() {
        Stm8PeripheralPack pack = packRegistry.packForFamily("STM8S").orElseThrow();
        Stm8Peripheral uart1 = pack.findPeripheral("UART1").orElseThrow();

        String plate = Stm8PeripheralSchemaTransform.formatPeripheralPlateComment(uart1);
        assertNotNull(plate);
        assertTrue(plate.contains("=== STM8 UART1 Peripheral Block ==="));
        assertTrue(plate.contains("Registers:"));

        Stm8Register sr = uart1.findRegisterByName("UART1_SR").orElseThrow();
        String eol = Stm8PeripheralSchemaTransform.formatRegisterComment(sr);
        assertNotNull(eol);
        assertTrue(eol.contains("UART1_SR"));
        assertTrue(eol.contains("0x5230"));
        assertTrue(eol.contains("TXE"));
        assertTrue(eol.contains("TC"));
        assertTrue(eol.contains("RXNE"));
    }

    @Test
    void invalidBitfieldThrowsException() {
        assertThrows(IllegalArgumentException.class, () ->
            new Stm8BitField("INVALID", 7, 2, 0x180, "R/W", "Overflows byte boundary"));

        assertThrows(IllegalArgumentException.class, () ->
            new Stm8BitField("BAD_MASK", 0, 1, 0x03, "R/W", "Mask mismatch"));
    }

    @Test
    void missingPacksDirectoryFailsClosed() {
        assertThrows(DiagnosticException.class, () ->
            Stm8DevicePackRegistry.load(Path.of("nonexistent/packs/dir"),
                ParserLimits.defaults(), CancellationToken.none()));
    }
}
