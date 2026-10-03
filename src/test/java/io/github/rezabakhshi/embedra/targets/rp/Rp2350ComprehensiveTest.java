package io.github.rezabakhshi.embedra.targets.rp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.model.BootRelationshipType;
import io.github.rezabakhshi.embedra.core.model.CommunicationKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.SecurityDomainKind;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350Architecture;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350BootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350SecurityDomain;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalogLoader;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * T053 comprehensive unit tests for RP2350A/B and RP2354A/B providers:
 * dual Cortex-M33 / Hazard3 RISC-V architecture selection, TrustZone/security domains,
 * boot chain, OTP/security evidence, QMI/XIP/PSRAM, package/memory differences,
 * both-core startup, peripherals, and three PIO blocks.
 */
public class Rp2350ComprehensiveTest {

    private static RpDeviceCatalog catalog;

    private static RpTargetResolver resolver;


    @BeforeAll
    static void setUp() throws Exception {
        catalog = RpDeviceCatalogLoader.loadDefault();
        resolver = new RpTargetResolver(catalog);
    }

    @Test
    void testPartAndPackageDifferences() {
        Rp2350TargetProvider part2350A = (Rp2350TargetProvider) resolver.resolvePart("RP2350A").orElseThrow();
        assertEquals(30, part2350A.gpioCount());
        assertFalse(part2350A.siliconRecord().hasInternalFlash());

        Rp2350TargetProvider part2350B = (Rp2350TargetProvider) resolver.resolvePart("RP2350B").orElseThrow();
        assertEquals(48, part2350B.gpioCount());
        assertFalse(part2350B.siliconRecord().hasInternalFlash());

        Rp2350TargetProvider part2354A = partFor("RP2354A");
        assertEquals(30, part2354A.gpioCount());
        assertTrue(part2354A.siliconRecord().hasInternalFlash());
        assertEquals(2 * 1024 * 1024L, part2354A.siliconRecord().internalFlashBytes());

        Rp2350TargetProvider part2354B = partFor("RP2354B");
        assertEquals(48, part2354B.gpioCount());
        assertTrue(part2354B.siliconRecord().hasInternalFlash());
        assertEquals(2 * 1024 * 1024L, part2354B.siliconRecord().internalFlashBytes());
    }

    private Rp2350TargetProvider partFor(String partNumber) {
        return (Rp2350TargetProvider) resolver.resolvePart(partNumber).orElseThrow();
    }

    @Test
    void testDualArchitectureSelectionArmAndRiscv() {
        Rp2350TargetProvider provider = partFor("RP2350A");

        // 1. ARM Cortex-M33 mode
        LanguageSelection armLang = provider.selectLanguage(Rp2350TargetProvider.ARCH_ARM);
        assertEquals("ARM:LE:32:v8M", armLang.languageId());
        assertEquals("ARMv8-M", armLang.instructionSet());
        assertEquals("ARM:LE:32:v8-m", provider.ghidraLanguageId(Rp2350TargetProvider.ARCH_ARM));
        assertEquals("default", provider.ghidraCompilerSpec(Rp2350TargetProvider.ARCH_ARM));

        ExecutionTopology armTopo = provider.buildTopology(Rp2350TargetProvider.ARCH_ARM, null);
        assertEquals(SecurityDomainKind.SECURE, armTopo.processors().get(0).securityDomain().kind());
        assertEquals("ARMv8-M", armTopo.processors().get(0).instructionSet().orElseThrow());

        // Inactive architecture is NOT in topology (RP-004)
        assertFalse(armTopo.processors().stream().anyMatch(p -> p.instructionSet().orElse("").contains("RV32")));

        // 2. Hazard3 RISC-V mode
        LanguageSelection riscvLang = provider.selectLanguage(Rp2350TargetProvider.ARCH_RISCV);
        assertEquals("RISCV:LE:32:default", riscvLang.languageId());
        assertEquals("RV32IMAC", riscvLang.instructionSet());
        assertEquals("RISCV:LE:32:default", provider.ghidraLanguageId(Rp2350TargetProvider.ARCH_RISCV));
        assertEquals("gcc", provider.ghidraCompilerSpec(Rp2350TargetProvider.ARCH_RISCV));

        ExecutionTopology riscvTopo = provider.buildTopology(Rp2350TargetProvider.ARCH_RISCV, null);
        assertEquals(SecurityDomainKind.NON_SECURE, riscvTopo.processors().get(0).securityDomain().kind());
        assertEquals("RV32IMAC", riscvTopo.processors().get(0).instructionSet().orElseThrow());

        // Inactive architecture is NOT in topology (RP-004)
        assertFalse(riscvTopo.processors().stream().anyMatch(p -> p.instructionSet().orElse("").contains("ARM")));
    }

    @Test
    void testRp2350ExecutionTopologyEnrichment() {
        Rp2350TargetProvider provider = partFor("RP2350A");
        ExecutionTopology topo = provider.buildTopology(Rp2350TargetProvider.ARCH_ARM, null);

        assertEquals(8, topo.processors().size());
        assertEquals(ProgramStrategy.SHARED_PROGRAM, topo.programStrategy());

        // Core 0 & Core 1
        ProcessorNode core0 = topo.processors().stream()
                .filter(p -> "rp2350.core0".equals(p.id())).findFirst().orElseThrow();
        ProcessorNode core1 = topo.processors().stream()
                .filter(p -> "rp2350.core1".equals(p.id())).findFirst().orElseThrow();

        assertEquals(ProcessorKind.CPU_CORE, core0.kind());
        assertEquals("BOOT_CORE", core0.role());
        assertEquals(ProcessorKind.CPU_CORE, core1.kind());
        assertEquals("SECONDARY_CORE", core1.role());

        // BootROM
        ProcessorNode bootrom = topo.processors().stream()
                .filter(p -> "rp2350.bootrom".equals(p.id())).findFirst().orElseThrow();
        assertEquals(ProcessorKind.BOOT_ROM, bootrom.kind());

        // Three PIO blocks
        ProcessorNode pio0 = topo.processors().stream()
                .filter(p -> "rp2350.pio0".equals(p.id())).findFirst().orElseThrow();
        ProcessorNode pio1 = topo.processors().stream()
                .filter(p -> "rp2350.pio1".equals(p.id())).findFirst().orElseThrow();
        ProcessorNode pio2 = topo.processors().stream()
                .filter(p -> "rp2350.pio2".equals(p.id())).findFirst().orElseThrow();
        assertEquals(ProcessorKind.PROGRAMMABLE_COPROCESSOR, pio0.kind());
        assertEquals(ProcessorKind.PROGRAMMABLE_COPROCESSOR, pio1.kind());
        assertEquals(ProcessorKind.PROGRAMMABLE_COPROCESSOR, pio2.kind());

        // Hardware accelerators
        ProcessorNode sha256 = topo.processors().stream()
                .filter(p -> "rp2350.sha256".equals(p.id())).findFirst().orElseThrow();
        ProcessorNode trng = topo.processors().stream()
                .filter(p -> "rp2350.trng".equals(p.id())).findFirst().orElseThrow();
        assertEquals(ProcessorKind.FIXED_FUNCTION_ACCELERATOR, sha256.kind());
        assertEquals(ProcessorKind.FIXED_FUNCTION_ACCELERATOR, trng.kind());


        // Both-core startup relationship
        assertEquals(1, topo.bootRelationships().size());
        assertEquals("rp2350.core0_launches_core1", topo.bootRelationships().get(0).id());
        assertEquals(BootRelationshipType.RELEASES_FROM_RESET, topo.bootRelationships().get(0).type());

        // Communication links: FIFO, spinlocks, PIO0, PIO1, PIO2 interrupts
        assertEquals(5, topo.communicationLinks().size());
        assertTrue(topo.communicationLinks().stream().anyMatch(l -> "rp2350.sio_fifo".equals(l.id())));
        assertTrue(topo.communicationLinks().stream().anyMatch(l -> "rp2350.sio_spinlocks".equals(l.id())));
        assertTrue(topo.communicationLinks().stream().anyMatch(l -> "rp2350.pio0_interrupts".equals(l.id())));
        assertTrue(topo.communicationLinks().stream().anyMatch(l -> "rp2350.pio1_interrupts".equals(l.id())));
        assertTrue(topo.communicationLinks().stream().anyMatch(l -> "rp2350.pio2_interrupts".equals(l.id())));

        // Shared memories: SRAM (520K) and OTP (8K)
        assertEquals(2, topo.sharedMemories().size());
        assertTrue(topo.sharedMemories().stream().anyMatch(m -> "rp2350.shared_sram".equals(m.id())));
        assertTrue(topo.sharedMemories().stream().anyMatch(m -> "rp2350.shared_otp".equals(m.id())));
    }

    @Test
    void testRp2350MemoryRegionsAndPsram() {
        Rp2350TargetProvider provider = partFor("RP2350A");
        RpBoardProfile pico2 = catalog.findBoardProfile("pico2").orElseThrow();
        List<RpMemoryRegion> regions = provider.memoryRegions(pico2);

        assertTrue(regions.stream().anyMatch(r -> "BOOT_ROM".equals(r.id()) && r.range().length() == 0x8000L));
        assertTrue(regions.stream().anyMatch(r -> "FLASH".equals(r.id()) && r.range().start() == 0x10000000L));
        assertTrue(regions.stream().anyMatch(r -> "PSRAM".equals(r.id()) && r.range().start() == 0x11000000L));
        assertTrue(regions.stream().anyMatch(
                r -> "SRAM".equals(r.id()) && r.range().start() == 0x20000000L
                        && r.range().length() == 520 * 1024L));
        assertTrue(regions.stream().anyMatch(r -> "OTP".equals(r.id()) && r.range().start() == 0x40130000L));
        assertTrue(regions.stream().anyMatch(r -> "PERIPHERALS".equals(r.id()) && r.range().start() == 0x40000000L));
        assertTrue(regions.stream().anyMatch(r -> "ATOMIC_ALIASES".equals(r.id()) && r.range().start() == 0x50000000L));
    }

    @Test
    void testRp2350VectorTable() {
        assertEquals(16, Rp2350VectorTable.ARM_CORE_VECTOR_COUNT);
        assertEquals(52, Rp2350VectorTable.ARM_USER_IRQ_COUNT);
        assertEquals(68, Rp2350VectorTable.ARM_TOTAL_VECTOR_COUNT);

        assertEquals(Optional.of("__initial_sp"), Rp2350VectorTable.armVectorName(0));
        assertEquals(Optional.of("Reset_Handler"), Rp2350VectorTable.armVectorName(1));
        assertEquals(Optional.of("MemManage_Handler"), Rp2350VectorTable.armVectorName(4));
        assertEquals(Optional.of("SecureFault_Handler"), Rp2350VectorTable.armVectorName(7));

        assertEquals(Optional.of("TIMER0_IRQ_0"), Rp2350VectorTable.armIrqName(0));
        assertEquals(Optional.of("PIO2_IRQ_0"), Rp2350VectorTable.armIrqName(19));
        assertEquals(Optional.of("PIO2_IRQ_1"), Rp2350VectorTable.armIrqName(20));
        assertEquals(Optional.of("TRNG_IRQ"), Rp2350VectorTable.armIrqName(38));
        assertEquals(Optional.of("SHA256_IRQ"), Rp2350VectorTable.armIrqName(39));

        assertEquals(Optional.of("reset_vector"), Rp2350VectorTable.riscvVectorName(0));
        assertEquals(Optional.of("trap_entry"), Rp2350VectorTable.riscvVectorName(1));
    }

    @Test
    void testRp2350OtpMemory() {
        assertEquals(0x40130000L, Rp2350OtpMemory.OTP_BASE);
        assertEquals(8192L, Rp2350OtpMemory.OTP_SIZE_BYTES);

        assertTrue(Rp2350OtpMemory.containsAddress(0x40130000L));
        assertTrue(Rp2350OtpMemory.containsAddress(0x40131FFFL));
        assertFalse(Rp2350OtpMemory.containsAddress(0x40132000L));

        assertTrue(Rp2350OtpMemory.rowDescription(Rp2350OtpMemory.ROW_CHIP_ID).orElseThrow().contains("Chip"));
        assertTrue(Rp2350OtpMemory.rowDescription(Rp2350OtpMemory.ROW_BOOT_FLAGS).orElseThrow().contains("Boot"));
        assertTrue(Rp2350OtpMemory.rowDescription(
                Rp2350OtpMemory.ROW_SECURE_BOOT_KEY0).orElseThrow().contains("Key Slot 0"));
        assertTrue(Rp2350OtpMemory.rowDescription(
                Rp2350OtpMemory.ROW_SECURE_BOOT_KEY1).orElseThrow().contains("Key Slot 1"));
        assertTrue(Rp2350OtpMemory.rowDescription(
                Rp2350OtpMemory.ROW_ROLLBACK_LIMIT).orElseThrow().contains("Rollback"));
    }

    @Test
    void testRp2350ThreePioBlocks() {
        Rp2350TargetProvider provider = partFor("RP2350A");
        List<RpPioBlock> blocks = provider.pioBlocks();
        assertEquals(3, blocks.size());

        assertEquals("PIO0", blocks.get(0).blockName());
        assertEquals("PIO1", blocks.get(1).blockName());
        assertEquals("PIO2", blocks.get(2).blockName());
        assertEquals(0x50400000L, blocks.get(2).baseAddress());
        assertTrue(blocks.get(2).containsAddress(0x50400010L));
    }

    @Test
    void testRp2350BootChain() {
        Rp2350BootMetadata meta = new Rp2350BootMetadata(
                0x10000000L, 0x10000000L, true,
                Rp2350Architecture.ARM, Rp2350SecurityDomain.SECURE,
                OptionalLong.of(0x10000100L), 0x10000201L,
                OptionalLong.of(0x20080000L), false,
                List.of());
        Rp2350BootChain chain = new Rp2350BootChain(meta);

        assertEquals(Rp2350Architecture.ARM, chain.targetArchitecture());
        assertEquals(Rp2350SecurityDomain.SECURE, chain.securityDomain());
        assertTrue(chain.isTrustZoneSecure());
        assertEquals(Optional.of(0x10000100L), chain.vectorTableAddress());
        assertEquals(0x10000201L, chain.executionEntryPoint());
    }
}
