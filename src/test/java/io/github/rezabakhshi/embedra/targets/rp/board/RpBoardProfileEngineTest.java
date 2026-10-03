package io.github.rezabakhshi.embedra.targets.rp.board;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.rp.RpMemoryRegion;
import io.github.rezabakhshi.embedra.targets.rp.RpMemoryRegionKind;
import io.github.rezabakhshi.embedra.targets.rp.RpTargetProvider;
import io.github.rezabakhshi.embedra.targets.rp.RpTargetResolver;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalogLoader;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpSiliconRecord;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RpBoardProfileEngineTest {

    private static RpDeviceCatalog catalog;

    private static RpTargetResolver resolver;

    @BeforeAll
    static void setUp() throws Exception {
        catalog = RpDeviceCatalogLoader.loadDefault();
        resolver = new RpTargetResolver(catalog);
    }

    @Test
    void testPicoBoardPlan() throws Exception {
        RpBoardProfile pico = catalog.requireBoardProfile("pico");
        RpSiliconRecord rp2040 = catalog.requireExactPart("RP2040");

        RpBoardPlan plan = RpBoardProfileEngine.plan(pico, rp2040);
        assertNotNull(plan);
        assertEquals("pico", plan.profile().profileId());
        assertEquals("Raspberry Pi Pico", plan.profile().boardName());
        assertEquals("RP2040", plan.silicon().exactPart());
        assertEquals(2 * 1024 * 1024L, plan.flashBytes());
        assertEquals("Winbond W25Q16JV", plan.flashChip());
        assertEquals("QSPI", plan.flashInterface());
        assertEquals(0x10000000L, plan.flashBase());
        assertFalse(plan.hasWireless());

        List<RpPinAllocation> pins = plan.pinAllocations();
        assertEquals(1, pins.size());
        assertEquals(25, pins.get(0).pin());
        assertEquals("USER_LED", pins.get(0).role());

        // Target provider memory regions reflecting board plan
        RpTargetProvider provider = resolver.createProvider(rp2040);
        List<RpMemoryRegion> regions = provider.memoryRegions(pico);
        RpMemoryRegion flash = regions.stream()
                .filter(r -> r.kind() == RpMemoryRegionKind.FLASH_XIP)
                .findFirst()
                .orElseThrow();
        assertEquals(2 * 1024 * 1024L, flash.range().length());
    }

    @Test
    void testPicoWBoardPlan() throws Exception {
        RpBoardProfile picoW = catalog.requireBoardProfile("pico_w");
        RpSiliconRecord rp2040 = catalog.requireExactPart("RP2040");

        RpBoardPlan plan = RpBoardProfileEngine.plan(picoW, rp2040);
        assertNotNull(plan);
        assertEquals("pico_w", plan.profile().profileId());
        assertEquals("RP2040", plan.silicon().exactPart());
        assertEquals(2 * 1024 * 1024L, plan.flashBytes());
        assertEquals("QSPI", plan.flashInterface());
        assertTrue(plan.hasWireless());
        assertTrue(plan.wirelessChip().isPresent());
        assertEquals("Infineon CYW43439", plan.wirelessChip().get().model());
        assertTrue(plan.wirelessChip().get().interfaces().contains("SPI"));
        assertTrue(plan.wirelessChip().get().interfaces().contains("PIO"));

        List<RpPinAllocation> pins = plan.pinAllocations();
        assertEquals(4, pins.size());
        assertTrue(pins.stream().anyMatch(p -> p.pin() == 23 && "WL_ON".equals(p.name())));
        assertTrue(pins.stream().anyMatch(p -> p.pin() == 24 && "WL_DATA".equals(p.name())));
        assertTrue(pins.stream().anyMatch(p -> p.pin() == 25 && "WL_CS".equals(p.name())));
        assertTrue(pins.stream().anyMatch(p -> p.pin() == 29 && "WL_CLK".equals(p.name())));
    }

    @Test
    void testPico2BoardPlan() throws Exception {
        RpBoardProfile pico2 = catalog.requireBoardProfile("pico2");
        RpSiliconRecord rp2350a = catalog.requireExactPart("RP2350A");

        RpBoardPlan plan = RpBoardProfileEngine.plan(pico2, rp2350a);
        assertNotNull(plan);
        assertEquals("pico2", plan.profile().profileId());
        assertEquals("RP2350A", plan.silicon().exactPart());
        assertEquals(4 * 1024 * 1024L, plan.flashBytes());
        assertEquals("Winbond W25Q32RV", plan.flashChip());
        assertEquals("QMI", plan.flashInterface());
        assertFalse(plan.hasWireless());

        List<RpPinAllocation> pins = plan.pinAllocations();
        assertEquals(1, pins.size());
        assertEquals(25, pins.get(0).pin());
        assertEquals("USER_LED", pins.get(0).role());

        RpTargetProvider provider = resolver.createProvider(rp2350a);
        List<RpMemoryRegion> regions = provider.memoryRegions(pico2);
        RpMemoryRegion flash = regions.stream()
                .filter(r -> r.kind() == RpMemoryRegionKind.FLASH_XIP)
                .findFirst()
                .orElseThrow();
        assertEquals(4 * 1024 * 1024L, flash.range().length());
    }

    @Test
    void testPico2WBoardPlan() throws Exception {
        RpBoardProfile pico2W = catalog.requireBoardProfile("pico2_w");
        RpSiliconRecord rp2350a = catalog.requireExactPart("RP2350A");

        RpBoardPlan plan = RpBoardProfileEngine.plan(pico2W, rp2350a);
        assertNotNull(plan);
        assertEquals("pico2_w", plan.profile().profileId());
        assertEquals("RP2350A", plan.silicon().exactPart());
        assertEquals(4 * 1024 * 1024L, plan.flashBytes());
        assertEquals("QMI", plan.flashInterface());
        assertTrue(plan.hasWireless());
        assertEquals("Infineon CYW43439", plan.wirelessChip().get().model());
    }

    @Test
    void testIncompatibleBoardAndSiliconMismatchFailsClosed() {
        RpBoardProfile pico = catalog.requireBoardProfile("pico"); // requires RP2040
        RpSiliconRecord rp2350a = catalog.requireExactPart("RP2350A");

        DiagnosticException ex = assertThrows(DiagnosticException.class,
                () -> RpBoardProfileEngine.plan(pico, rp2350a));
        assertEquals(DiagnosticCode.RP_BOARD_MISMATCH, ex.diagnostic().code());
        assertFalse(RpBoardProfileEngine.isCompatible(pico, rp2350a));

        RpBoardProfile pico2 = catalog.requireBoardProfile("pico2"); // requires RP2350A
        RpSiliconRecord rp2040 = catalog.requireExactPart("RP2040");
        assertThrows(DiagnosticException.class, () -> RpBoardProfileEngine.plan(pico2, rp2040));
    }

    @Test
    void testResolverWithBoardAndPartIntegration() throws Exception {
        // Resolve pico_w board
        Optional<RpTargetResolver.RpTargetResolution> resPicoW = resolver.resolveTarget("RP2040", "pico_w");
        assertTrue(resPicoW.isPresent());
        assertEquals("RP2040", resPicoW.get().provider().siliconRecord().exactPart());
        assertTrue(resPicoW.get().boardProfile().isPresent());
        assertEquals("pico_w", resPicoW.get().boardProfile().get().profileId());
        assertTrue(resPicoW.get().boardPlan().isPresent());
        assertEquals(2 * 1024 * 1024L, resPicoW.get().boardPlan().get().flashBytes());

        // Resolve by board only
        Optional<RpTargetResolver.RpTargetResolution> resByBoardOnly = resolver.resolveTarget(null, "pico2");
        assertTrue(resByBoardOnly.isPresent());
        assertEquals("RP2350A", resByBoardOnly.get().provider().siliconRecord().exactPart());
        assertEquals("pico2", resByBoardOnly.get().boardProfile().get().profileId());

        // Incompatible part and board resolution returns empty
        Optional<RpTargetResolver.RpTargetResolution> resMismatch = resolver.resolveTarget("RP2350A", "pico");
        assertTrue(resMismatch.isEmpty());

        // Silicon only resolution
        Optional<RpTargetResolver.RpTargetResolution> resPartOnly = resolver.resolveTarget("RP2040", null);
        assertTrue(resPartOnly.isPresent());
        assertTrue(resPartOnly.get().boardProfile().isEmpty());
    }

    @Test
    void testBoardProfileEngineHelperMethods() throws Exception {
        Optional<RpBoardPlan> plan1 = RpBoardProfileEngine.plan("pico", catalog);
        assertTrue(plan1.isPresent());
        assertEquals("pico", plan1.get().profile().profileId());

        Optional<RpBoardPlan> plan2 = RpBoardProfileEngine.plan("pico2", "RP2350A", catalog);
        assertTrue(plan2.isPresent());
        assertEquals("pico2", plan2.get().profile().profileId());

        assertFalse(RpBoardProfileEngine.plan("non_existent", catalog).isPresent());
    }
}
