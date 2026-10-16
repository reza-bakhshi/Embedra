package io.github.rezabakhshi.embedra.targets.atmel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelAddressModel;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelCatalogRegistry;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Automated tests for AtmelCatalogRegistry.
 */
class AtmelCatalogRegistryTest {

    private AtmelCatalogRegistry registry;

    @BeforeEach
    void setUp() throws DiagnosticException {
        registry = AtmelCatalogRegistry.loadDefault();
    }

    @Test
    void loadDefaultCatalogSuccessfully() {
        assertNotNull(registry);
        assertEquals(27, registry.size(), "Catalog should contain 27 exact parts");
        assertEquals(27, registry.allParts().size());
    }

    @Test
    void representativePartsPresentWithExactParameters() throws DiagnosticException {
        // ATmega328P
        AtmelPartRecord m328 = registry.getPart("ATmega328P");
        assertEquals("ATmega328P", m328.exactPart());
        assertEquals("AVR", m328.family());
        assertEquals("ATmega", m328.series());
        assertEquals("avr8:LE:16:default", m328.ghidraLanguage());
        assertEquals(AtmelAddressModel.HARVARD_SEPARATE, m328.addressModel());
        assertEquals(32768L, m328.flashBytes());
        assertEquals(2048L, m328.ramBytes());
        assertEquals(1024L, m328.eepromBytes());
        assertEquals(26, m328.vectorCount());
        assertEquals(4, m328.vectorStrideBytes());
        assertEquals(SupportState.SUPPORTED, m328.supportState());

        // ATmega2560
        AtmelPartRecord m2560 = registry.getPart("ATmega2560");
        assertEquals("avr8:LE:24:default", m2560.ghidraLanguage());
        assertEquals(262144L, m2560.flashBytes());
        assertEquals(8192L, m2560.ramBytes());
        assertEquals(57, m2560.vectorCount());
        assertEquals(SupportState.SUPPORTED, m2560.supportState());

        // ATtiny85
        AtmelPartRecord t85 = registry.getPart("ATtiny85");
        assertEquals("ATtiny", t85.series());
        assertEquals(8192L, t85.flashBytes());
        assertEquals(512L, t85.ramBytes());
        assertEquals(15, t85.vectorCount());
        assertEquals(2, t85.vectorStrideBytes());
        assertEquals("RJMP", t85.vectorInstruction());
        assertEquals(SupportState.SUPPORTED, t85.supportState());

        // AVR128DA48
        AtmelPartRecord da48 = registry.getPart("AVR128DA48");
        assertEquals("AVR-Dx", da48.series());
        assertEquals("avr8:LE:24:xmega", da48.ghidraLanguage());
        assertEquals(AtmelAddressModel.HARVARD_UNIFIED_DATA_ALIAS, da48.addressModel());
        assertEquals(131072L, da48.flashBytes());
        assertEquals(16384L, da48.ramBytes());
        assertTrue(da48.hasFlashDataAlias());
        assertEquals(0x8000L, da48.flashDataAliasStart());
        assertEquals(SupportState.PLANNED, da48.supportState());

        // SAMD21G18A
        AtmelPartRecord samd = registry.getPart("SAMD21G18A");
        assertEquals("SAM", samd.family());
        assertEquals("SAMD", samd.series());
        assertEquals("ARM:LE:32:v6M", samd.ghidraLanguage());
        assertEquals(AtmelAddressModel.LINEAR_32BIT, samd.addressModel());
        assertEquals(262144L, samd.flashBytes());
        assertEquals(32768L, samd.ramBytes());
        assertEquals(0x20000000L, samd.ramStart());
        assertEquals(SupportState.SUPPORTED, samd.supportState());

        // SAME70Q21
        AtmelPartRecord same = registry.getPart("SAME70Q21");
        assertEquals("SAME", same.series());
        assertEquals("ARM:LE:32:v7EM", same.ghidraLanguage());
        assertEquals(AtmelAddressModel.LINEAR_32BIT, same.addressModel());
        assertEquals(2097152L, same.flashBytes());
        assertEquals(0x00400000L, same.flashStart());
        assertEquals(0x20400000L, same.ramStart());
        assertEquals(SupportState.SUPPORTED, same.supportState());
    }

    @Test
    void filterByFamilyAndSeries() {
        List<AtmelPartRecord> avrParts = registry.partsByFamily("AVR");
        assertEquals(18, avrParts.size(), "18 AVR parts: 7 ATmega + 6 ATtiny + 5 AVR-Dx");

        List<AtmelPartRecord> samParts = registry.partsByFamily("SAM");
        assertEquals(9, samParts.size(), "9 SAM parts: 5 SAMD + 4 SAME");

        List<AtmelPartRecord> megaParts = registry.partsBySeries("ATmega");
        assertEquals(7, megaParts.size());

        List<AtmelPartRecord> tinyParts = registry.partsBySeries("ATtiny");
        assertEquals(6, tinyParts.size());

        List<AtmelPartRecord> dxParts = registry.partsBySeries("AVR-Dx");
        assertEquals(5, dxParts.size());
    }

    @Test
    void findPartRejectsWildcardsAndGenericPrefixes() {
        // Exact match works
        Optional<AtmelPartRecord> found = registry.findPart("ATmega328P");
        assertTrue(found.isPresent());

        // Case-insensitive exact match works
        Optional<AtmelPartRecord> caseInsensitive = registry.findPart("atmega328p");
        assertTrue(caseInsensitive.isPresent());

        // Wildcards are rejected
        assertFalse(registry.findPart("ATmega*").isPresent());
        assertFalse(registry.findPart("*").isPresent());
        assertFalse(registry.findPart("ATmega328?").isPresent());

        // Generic family prefixes are rejected
        assertFalse(registry.findPart("AVR").isPresent());
        assertFalse(registry.findPart("ATMEL").isPresent());
        assertFalse(registry.findPart("ATMEGA").isPresent());
        assertFalse(registry.findPart("SAM").isPresent());
    }

    @Test
    void getPartThrowsDiagnosticExceptionOnInvalidQueries() {
        // Wildcard query throws ATMEL_ENTRY_REJECTED
        DiagnosticException de1 = assertThrows(DiagnosticException.class, () -> registry.getPart("ATmega*"));
        assertEquals(DiagnosticCode.ATMEL_ENTRY_REJECTED, de1.diagnostic().code());

        // Family prefix query throws ATMEL_ENTRY_REJECTED
        DiagnosticException de2 = assertThrows(DiagnosticException.class, () -> registry.getPart("AVR"));
        assertEquals(DiagnosticCode.ATMEL_ENTRY_REJECTED, de2.diagnostic().code());

        // Unknown part throws ATMEL_TARGET_UNSUPPORTED
        DiagnosticException de3 = assertThrows(DiagnosticException.class, () -> registry.getPart("ATmega99999"));
        assertEquals(DiagnosticCode.ATMEL_TARGET_UNSUPPORTED, de3.diagnostic().code());
    }

    @Test
    void cancellationIsHonoredDuringLoad() {
        CancellationToken token = () -> true;
        assertThrows(DiagnosticException.class, () ->
            AtmelCatalogRegistry.load(Path.of("catalogs/atmel/2026-10-14"), ParserLimits.defaults(), token)
        );
    }

    @Test
    void parserLimitsExceededThrows() {
        ParserLimits limits = new ParserLimits(
            10, 10, 10, 10, 10, java.time.Duration.ofSeconds(1)
        );
        assertThrows(DiagnosticException.class, () ->
            AtmelCatalogRegistry.load(Path.of("catalogs/atmel/2026-10-14"), limits, CancellationToken.none())
        );
    }
}
