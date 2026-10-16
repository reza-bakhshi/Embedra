package io.github.rezabakhshi.embedra.targets.nordic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicCatalogRegistry;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import io.github.rezabakhshi.embedra.targets.nordic.dualcore.NordicDualCoreAnalyzer;
import io.github.rezabakhshi.embedra.targets.nordic.dualcore.NordicDualCoreLayout;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for NordicDualCoreAnalyzer (T099).
 */
class NordicDualCoreAnalyzerTest {

    private NordicCatalogRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        registry = NordicCatalogRegistry.loadDefault();
    }

    @Test
    void buildLayoutProducesValidPartitionsForNrf5340() throws Exception {
        NordicPartRecord nrf5340 = registry.findExactPart("nRF5340-QKAA").orElseThrow();
        NordicDualCoreLayout layout = NordicDualCoreAnalyzer.buildLayout(nrf5340);

        assertNotNull(layout);
        assertEquals(0x00000000L, layout.appCoreFlash().start());
        assertEquals(1048576L, layout.appCoreFlash().length());
        assertEquals(0x20000000L, layout.appCoreRam().start());
        assertEquals(524288L, layout.appCoreRam().length());

        assertEquals(0x01000000L, layout.netCoreFlashGlobal().start());
        assertEquals(262144L, layout.netCoreFlashGlobal().length());
        assertEquals(0x21000000L, layout.netCoreRamGlobal().start());
        assertEquals(65536L, layout.netCoreRamGlobal().length());

        assertEquals(16, layout.ipcChannels());
    }

    @Test
    void buildLayoutThrowsOnSingleCorePart() {
        NordicPartRecord nrf52840 = registry.findExactPart("nRF52840-QIAA").orElseThrow();
        assertThrows(DiagnosticException.class, () ->
            NordicDualCoreAnalyzer.buildLayout(nrf52840)
        );
    }

    @Test
    void addressClassificationSeparatesApplicationAndNetworkSpaces() {
        // App flash and RAM
        assertTrue(NordicDualCoreAnalyzer.isApplicationCoreAddress(0x00000100L));
        assertTrue(NordicDualCoreAnalyzer.isApplicationCoreAddress(0x20004000L));
        assertFalse(NordicDualCoreAnalyzer.isApplicationCoreAddress(0x01000100L));
        assertFalse(NordicDualCoreAnalyzer.isApplicationCoreAddress(0x21004000L));

        // Net flash and RAM (global map)
        assertTrue(NordicDualCoreAnalyzer.isNetworkCoreAddress(0x01000100L));
        assertTrue(NordicDualCoreAnalyzer.isNetworkCoreAddress(0x21004000L));
        assertFalse(NordicDualCoreAnalyzer.isNetworkCoreAddress(0x00000100L));
        assertFalse(NordicDualCoreAnalyzer.isNetworkCoreAddress(0x20004000L));
    }
}
