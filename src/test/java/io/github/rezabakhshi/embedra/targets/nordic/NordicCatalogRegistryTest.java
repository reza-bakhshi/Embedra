package io.github.rezabakhshi.embedra.targets.nordic;

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
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicCatalogRegistry;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for NordicCatalogRegistry (T098).
 */
class NordicCatalogRegistryTest {

    private NordicCatalogRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        registry = NordicCatalogRegistry.loadDefault();
    }

    @Test
    void loadDefaultLoadsAllTwentyOneParts() {
        assertNotNull(registry);
        assertEquals(21, registry.size());
        assertEquals(21, registry.allParts().size());
    }

    @Test
    void exactPartLookupSucceedsForRepresentativeParts() {
        List<String> supportedParts = List.of(
            "nRF51822-QFAA", "nRF52832-QFAA", "nRF52840-QIAA", "nRF5340-QKAA", "nRF9160-SICA"
        );
        for (String partName : supportedParts) {
            Optional<NordicPartRecord> opt = registry.findExactPart(partName);
            assertTrue(opt.isPresent(), "Part should be found: " + partName);
            NordicPartRecord part = opt.get();
            assertEquals(partName, part.exactPart());
            assertEquals(SupportState.SUPPORTED, part.supportState());
        }

        List<String> plannedParts = List.of(
            "nRF51822-QFAC", "nRF51802-QFAA", "nRF52810-QCAA", "nRF52833-QIAA", "nRF54L15", "nRF54H20"
        );
        for (String partName : plannedParts) {
            Optional<NordicPartRecord> opt = registry.findExactPart(partName);
            assertTrue(opt.isPresent(), "Part should be found: " + partName);
            NordicPartRecord part = opt.get();
            assertEquals(partName, part.exactPart());
            assertEquals(SupportState.PLANNED, part.supportState());
        }
    }

    @Test
    void exactPartLookupRejectsWildcardsAndBarePrefixes() {
        // Wildcards rejected
        assertTrue(registry.findExactPart("nRF52*").isEmpty());
        assertTrue(registry.findExactPart("*").isEmpty());
        assertTrue(registry.findExactPart("nRF52840?").isEmpty());

        // Bare family prefixes rejected
        assertTrue(registry.findExactPart("nRF51").isEmpty());
        assertTrue(registry.findExactPart("nRF52").isEmpty());
        assertTrue(registry.findExactPart("nRF53").isEmpty());
        assertTrue(registry.findExactPart("nRF54").isEmpty());
        assertTrue(registry.findExactPart("nRF91").isEmpty());

        // Null and blank rejected
        assertTrue(registry.findExactPart(null).isEmpty());
        assertTrue(registry.findExactPart("").isEmpty());
        assertTrue(registry.findExactPart("   ").isEmpty());
    }

    @Test
    void partsBySeriesFiltersCorrectly() {
        List<NordicPartRecord> nrf51Parts = registry.partsBySeries("nRF51");
        assertEquals(5, nrf51Parts.size());

        List<NordicPartRecord> nrf52Parts = registry.partsBySeries("nRF52");
        assertEquals(10, nrf52Parts.size());

        List<NordicPartRecord> nrf53Parts = registry.partsBySeries("nRF53");
        assertEquals(2, nrf53Parts.size());

        List<NordicPartRecord> nrf54Parts = registry.partsBySeries("nRF54");
        assertEquals(2, nrf54Parts.size());

        List<NordicPartRecord> nrf91Parts = registry.partsBySeries("nRF91");
        assertEquals(2, nrf91Parts.size());
    }

    @Test
    void cryptoCellPresenceDetectedCorrectly() {
        NordicPartRecord nrf52840 = registry.findExactPart("nRF52840-QIAA").orElseThrow();
        assertTrue(nrf52840.hasCryptoCell());
        assertEquals(0x5002A000L, nrf52840.cryptoCellBase());

        NordicPartRecord nrf52832 = registry.findExactPart("nRF52832-QFAA").orElseThrow();
        assertFalse(nrf52832.hasCryptoCell());

        NordicPartRecord nrf5340 = registry.findExactPart("nRF5340-QKAA").orElseThrow();
        assertTrue(nrf5340.hasCryptoCell());
        assertEquals(0x50840000L, nrf5340.cryptoCellBase());

        NordicPartRecord nrf9160 = registry.findExactPart("nRF9160-SICA").orElseThrow();
        assertTrue(nrf9160.hasCryptoCell());
        assertEquals(0x50840000L, nrf9160.cryptoCellBase());
    }

    @Test
    void dualCoreAndTrustZoneFlagsReflectHardware() {
        NordicPartRecord nrf5340 = registry.findExactPart("nRF5340-QKAA").orElseThrow();
        assertTrue(nrf5340.dualCore());
        assertTrue(nrf5340.trustZone());

        NordicPartRecord nrf9160 = registry.findExactPart("nRF9160-SICA").orElseThrow();
        assertFalse(nrf9160.dualCore());
        assertTrue(nrf9160.trustZone());

        NordicPartRecord nrf52840 = registry.findExactPart("nRF52840-QIAA").orElseThrow();
        assertFalse(nrf52840.dualCore());
        assertFalse(nrf52840.trustZone());
    }

    @Test
    void parserLimitsAndCancellationAreHonored() {
        ParserLimits tightLimits = new ParserLimits(10, 10, 10, 10, 10, Duration.ofSeconds(10));
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
            NordicCatalogRegistry.load(Path.of("catalogs/nordic/2026-10-13"), tightLimits, CancellationToken.none())
        );
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }
}
