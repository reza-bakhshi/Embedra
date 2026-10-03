package io.github.rezabakhshi.embedra.targets.rp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.model.BootRelationshipType;
import io.github.rezabakhshi.embedra.core.model.CommunicationKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.SecurityDomainKind;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalogLoader;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpSiliconRecord;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RpTargetProviderTest {

    private static RpDeviceCatalog catalog;

    private static RpTargetResolver resolver;

    @BeforeAll
    static void setUp() throws Exception {
        catalog = RpDeviceCatalogLoader.loadDefault();
        resolver = new RpTargetResolver(catalog);
    }

    @Test
    void testRp2040Provider() {
        Optional<RpTargetProvider> providerOpt = resolver.resolvePart("RP2040");
        assertTrue(providerOpt.isPresent(), "RP2040 should resolve");
        RpTargetProvider provider = providerOpt.get();
        assertEquals(Rp2040TargetProvider.PROVIDER_ID, provider.providerId());
        assertEquals("RP2040", provider.series());
        assertEquals("RP2040", provider.siliconRecord().exactPart());

        // Language selection
        LanguageSelection lang = provider.selectLanguage(Rp2040TargetProvider.ARCH_ARM);
        assertEquals("ARM:LE:32:v6M", lang.languageId());
        assertEquals("ARMv6-M", lang.instructionSet());

        // Memory regions
        Optional<RpBoardProfile> picoProfile = catalog.findBoardProfile("pico");
        assertTrue(picoProfile.isPresent());
        List<RpMemoryRegion> regions = provider.memoryRegions(picoProfile.get());
        assertTrue(regions.stream().anyMatch(
                r -> r.kind() == RpMemoryRegionKind.BOOT_ROM && r.range().length() == 0x4000L));
        assertTrue(regions.stream().anyMatch(
                r -> r.kind() == RpMemoryRegionKind.FLASH_XIP && r.range().length() == 2 * 1024 * 1024L));
        assertTrue(regions.stream().anyMatch(
                r -> r.kind() == RpMemoryRegionKind.SRAM && r.range().length() == 264 * 1024L));
        assertTrue(regions.stream().anyMatch(
                r -> r.kind() == RpMemoryRegionKind.SIO && r.range().start() == 0xD0000000L));

        // Address mapping
        assertTrue(provider.isAddressMapped(0x00001000L, picoProfile.get()));
        assertTrue(provider.isAddressMapped(0x10000100L, picoProfile.get()));
        assertTrue(provider.isAddressMapped(0x20000000L, picoProfile.get()));
        assertFalse(provider.isAddressMapped(0x30000000L, picoProfile.get()));

        // Entry points
        assertTrue(provider.isValidEntryPoint(0x10000101L, Rp2040TargetProvider.ARCH_ARM, picoProfile.get()));
        assertTrue(provider.isValidEntryPoint(0x20000001L, Rp2040TargetProvider.ARCH_ARM, picoProfile.get()));
        assertFalse(provider.isValidEntryPoint(
                0x40000001L, Rp2040TargetProvider.ARCH_ARM, picoProfile.get()));

        // Execution topology
        ExecutionTopology topo = provider.buildTopology(Rp2040TargetProvider.ARCH_ARM, picoProfile.get());
        assertEquals(5, topo.processors().size());
        assertEquals(2, topo.processors().stream()
                .filter(p -> p.kind() == io.github.rezabakhshi.embedra.core.model.ProcessorKind.CPU_CORE).count());
        assertEquals(ProgramStrategy.SHARED_PROGRAM, topo.programStrategy());

        ProcessorNode core0 = topo.processors().get(0);
        ProcessorNode core1 = topo.processors().get(1);
        assertEquals("rp2040.core0", core0.id());
        assertEquals("rp2040.core1", core1.id());
        assertEquals(SecurityDomainKind.NON_SECURE, core0.securityDomain().kind());

        // Boot relationship and communication links
        assertEquals(1, topo.bootRelationships().size());
        assertEquals(BootRelationshipType.RELEASES_FROM_RESET, topo.bootRelationships().get(0).type());
        assertEquals(4, topo.communicationLinks().size());
        assertTrue(topo.communicationLinks().stream().anyMatch(l -> l.kind() == CommunicationKind.FIFO));
        assertTrue(topo.communicationLinks().stream().anyMatch(
                l -> l.kind() == CommunicationKind.HARDWARE_SEMAPHORE));
    }

    @Test
    void testRp2350ProviderArmAndRiscv() {
        Optional<RpTargetProvider> providerOpt = resolver.resolvePart("RP2350A");
        assertTrue(providerOpt.isPresent(), "RP2350A should resolve");
        RpTargetProvider provider = providerOpt.get();
        assertEquals(Rp2350TargetProvider.PROVIDER_ID, provider.providerId());
        assertEquals("RP2350", provider.series());

        // ARM mode
        LanguageSelection armLang = provider.selectLanguage(Rp2350TargetProvider.ARCH_ARM);
        assertEquals("ARM:LE:32:v8M", armLang.languageId());
        assertEquals("ARMv8-M", armLang.instructionSet());

        ExecutionTopology armTopo = provider.buildTopology(Rp2350TargetProvider.ARCH_ARM, null);
        assertEquals(SecurityDomainKind.SECURE, armTopo.processors().get(0).securityDomain().kind());
        assertEquals("rp2350.trustzone_secure", armTopo.processors().get(0).securityDomain().id());

        // RISC-V mode
        LanguageSelection riscvLang = provider.selectLanguage(Rp2350TargetProvider.ARCH_RISCV);
        assertEquals("RISCV:LE:32:default", riscvLang.languageId());
        assertEquals("RV32IMAC", riscvLang.instructionSet());

        ExecutionTopology riscvTopo = provider.buildTopology(Rp2350TargetProvider.ARCH_RISCV, null);
        assertEquals(SecurityDomainKind.NON_SECURE, riscvTopo.processors().get(0).securityDomain().kind());

        // Memory map with board profile pico2 (4 MiB)
        Optional<RpBoardProfile> pico2Profile = catalog.findBoardProfile("pico2");
        assertTrue(pico2Profile.isPresent());
        List<RpMemoryRegion> regions = provider.memoryRegions(pico2Profile.get());
        assertTrue(regions.stream().anyMatch(
                r -> r.kind() == RpMemoryRegionKind.BOOT_ROM && r.range().length() == 0x8000L));
        assertTrue(regions.stream().anyMatch(
                r -> r.kind() == RpMemoryRegionKind.FLASH_XIP && r.range().length() == 4 * 1024 * 1024L));
        assertTrue(regions.stream().anyMatch(
                r -> r.kind() == RpMemoryRegionKind.SRAM && r.range().length() == 520 * 1024L));
        assertTrue(regions.stream().anyMatch(
                r -> r.kind() == RpMemoryRegionKind.OTP && r.range().start() == 0x40130000L && !r.writable()));
    }

    @Test
    void testRp2354InternalFlash() {
        Optional<RpTargetProvider> providerOpt = resolver.resolvePart("RP2354B");
        assertTrue(providerOpt.isPresent(), "RP2354B should resolve");
        RpTargetProvider provider = providerOpt.get();
        assertTrue(provider.siliconRecord().hasInternalFlash());
        assertEquals(2 * 1024 * 1024L, provider.siliconRecord().internalFlashBytes());

        List<RpMemoryRegion> regions = provider.memoryRegions(null);
        Optional<RpMemoryRegion> flashRegion = regions.stream().filter(r -> "FLASH".equals(r.id())).findFirst();
        assertTrue(flashRegion.isPresent());
        assertEquals(RpMemoryRegionKind.INTERNAL_FLASH, flashRegion.get().kind());
        assertEquals(2 * 1024 * 1024L, flashRegion.get().range().length());
    }

    @Test
    void testResolverByBoard() {
        Optional<RpTargetProvider> picoW = resolver.resolveBoard("pico_w");
        assertTrue(picoW.isPresent());
        assertEquals("RP2040", picoW.get().siliconRecord().exactPart());

        Optional<RpTargetProvider> pico2W = resolver.resolveBoard("pico2_w");
        assertTrue(pico2W.isPresent());
        assertEquals("RP2350A", pico2W.get().siliconRecord().exactPart());

        assertFalse(resolver.resolveBoard("non_existent_board").isPresent());
        assertFalse(resolver.resolvePart("RP9999").isPresent());
    }
}
