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
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalogLoader;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * T052 comprehensive unit tests for RP2040 ARMv6-M language, dual-core startup, XIP,
 * boot2, vector-table, SRAM, ROM, peripheral, atomic-alias, and two-PIO-block provider data.
 */
public class Rp2040ComprehensiveTest {

    private static RpDeviceCatalog catalog;

    private static RpTargetResolver resolver;


    @BeforeAll
    static void setUp() throws Exception {
        catalog = RpDeviceCatalogLoader.loadDefault();
        resolver = new RpTargetResolver(catalog);
    }

    @Test
    void testRp2040LanguageAndGhidraSpec() {
        Rp2040TargetProvider provider = (Rp2040TargetProvider) resolver.resolvePart("RP2040").orElseThrow();
        LanguageSelection lang = provider.selectLanguage(Rp2040TargetProvider.ARCH_ARM);
        assertEquals("ARM:LE:32:v6M", lang.languageId());
        assertEquals("ARMv6-M", lang.instructionSet());
        assertEquals(32, lang.addressSizeBits());
        assertEquals(2, lang.instructionAlignmentBytes());
        assertEquals("little", lang.endianness());

        assertEquals("ARM:LE:32:Cortex", provider.ghidraLanguageId());
        assertEquals("default", provider.ghidraCompilerSpec());
    }

    @Test
    void testRp2040DualCoreStartupAndTopology() {
        Rp2040TargetProvider provider = (Rp2040TargetProvider) resolver.resolvePart("RP2040").orElseThrow();
        RpBoardProfile pico = catalog.findBoardProfile("pico").orElseThrow();
        ExecutionTopology topo = provider.buildTopology(Rp2040TargetProvider.ARCH_ARM, pico);

        assertEquals(ProgramStrategy.SHARED_PROGRAM, topo.programStrategy());
        assertEquals(5, topo.processors().size());

        // Processors: Core 0, Core 1, BootROM, PIO0, PIO1
        ProcessorNode core0 = topo.processors().stream()
                .filter(p -> "rp2040.core0".equals(p.id())).findFirst().orElseThrow();
        ProcessorNode core1 = topo.processors().stream()
                .filter(p -> "rp2040.core1".equals(p.id())).findFirst().orElseThrow();
        ProcessorNode bootrom = topo.processors().stream()
                .filter(p -> "rp2040.bootrom".equals(p.id())).findFirst().orElseThrow();
        ProcessorNode pio0 = topo.processors().stream()
                .filter(p -> "rp2040.pio0".equals(p.id())).findFirst().orElseThrow();
        ProcessorNode pio1 = topo.processors().stream()
                .filter(p -> "rp2040.pio1".equals(p.id())).findFirst().orElseThrow();

        assertEquals(ProcessorKind.CPU_CORE, core0.kind());
        assertEquals("BOOT_CORE", core0.role());
        assertEquals(ProcessorKind.CPU_CORE, core1.kind());
        assertEquals("SECONDARY_CORE", core1.role());
        assertEquals(ProcessorKind.BOOT_ROM, bootrom.kind());
        assertEquals(ProcessorKind.PROGRAMMABLE_COPROCESSOR, pio0.kind());
        assertEquals(ProcessorKind.PROGRAMMABLE_COPROCESSOR, pio1.kind());

        assertEquals(SecurityDomainKind.NON_SECURE, core0.securityDomain().kind());
        assertEquals(SecurityDomainKind.NON_SECURE, core1.securityDomain().kind());

        // Dual-core launch relationship
        assertEquals(1, topo.bootRelationships().size());
        var bootRel = topo.bootRelationships().get(0);
        assertEquals("rp2040.core0_launches_core1", bootRel.id());
        assertEquals("rp2040.core0", bootRel.sourceNodeId());
        assertEquals("rp2040.core1", bootRel.targetNodeId());
        assertEquals(BootRelationshipType.RELEASES_FROM_RESET, bootRel.type());

        // Communication links: FIFO (SIO), spinlocks (semaphore), and PIO interrupts
        assertEquals(4, topo.communicationLinks().size());
        assertTrue(topo.communicationLinks().stream().anyMatch(
                l -> "rp2040.sio_fifo".equals(l.id()) && l.kind() == CommunicationKind.FIFO));
        assertTrue(topo.communicationLinks().stream().anyMatch(
                l -> "rp2040.sio_spinlocks".equals(l.id()) && l.kind() == CommunicationKind.HARDWARE_SEMAPHORE));
        assertTrue(topo.communicationLinks().stream().anyMatch(
                l -> "rp2040.pio0_interrupts".equals(l.id())));
        assertTrue(topo.communicationLinks().stream().anyMatch(
                l -> "rp2040.pio1_interrupts".equals(l.id())));

        // Shared SRAM
        assertEquals(1, topo.sharedMemories().size());
        var sram = topo.sharedMemories().get(0);
        assertEquals(264 * 1024L, sram.range().length());
        assertTrue(sram.readerNodeIds().contains("rp2040.core0"));
        assertTrue(sram.readerNodeIds().contains("rp2040.core1"));
    }

    @Test
    void testRp2040MemoryRegions() {
        Rp2040TargetProvider provider = (Rp2040TargetProvider) resolver.resolvePart("RP2040").orElseThrow();
        RpBoardProfile pico = catalog.findBoardProfile("pico").orElseThrow();
        List<RpMemoryRegion> regions = provider.memoryRegions(pico);

        // Verify all expected memory regions exist
        assertTrue(regions.stream().anyMatch(r -> "BOOT_ROM".equals(r.id()) && r.range().start() == 0x00000000L));
        assertTrue(regions.stream().anyMatch(r -> "FLASH_XIP".equals(r.id()) && r.range().start() == 0x10000000L));
        assertTrue(regions.stream().anyMatch(
                r -> "XIP_MAINTENANCE".equals(r.id()) && r.range().start() == 0x14000000L));
        assertTrue(regions.stream().anyMatch(
                r -> "SRAM".equals(r.id()) && r.range().start() == 0x20000000L
                        && r.range().length() == 264 * 1024L));
        assertTrue(regions.stream().anyMatch(
                r -> "NON_STRIPED_SRAM".equals(r.id()) && r.range().start() == 0x21000000L));
        assertTrue(regions.stream().anyMatch(r -> "PERIPHERALS".equals(r.id()) && r.range().start() == 0x40000000L));
        assertTrue(regions.stream().anyMatch(r -> "ATOMIC_ALIASES".equals(r.id()) && r.range().start() == 0x50000000L));
        assertTrue(regions.stream().anyMatch(r -> "SIO".equals(r.id()) && r.range().start() == 0xD0000000L));
        assertTrue(regions.stream().anyMatch(r -> "PPB".equals(r.id()) && r.range().start() == 0xE0000000L));
    }

    @Test
    void testRp2040VectorTable() {
        assertEquals(0x10000100L, Rp2040VectorTable.DEFAULT_FLASH_VECTOR_TABLE_OFFSET);
        assertEquals(48, Rp2040VectorTable.TOTAL_VECTOR_COUNT);
        assertEquals(192, Rp2040VectorTable.TABLE_SIZE_BYTES);

        // Core exceptions
        assertEquals(Optional.of("__initial_sp"), Rp2040VectorTable.vectorName(0));
        assertEquals(Optional.of("Reset_Handler"), Rp2040VectorTable.vectorName(1));
        assertEquals(Optional.of("NMI_Handler"), Rp2040VectorTable.vectorName(2));
        assertEquals(Optional.of("HardFault_Handler"), Rp2040VectorTable.vectorName(3));
        assertEquals(Optional.of("SVC_Handler"), Rp2040VectorTable.vectorName(11));
        assertEquals(Optional.of("PendSV_Handler"), Rp2040VectorTable.vectorName(14));
        assertEquals(Optional.of("SysTick_Handler"), Rp2040VectorTable.vectorName(15));

        // External user IRQs
        assertEquals(Optional.of("TIMER_IRQ_0"), Rp2040VectorTable.irqName(0));
        assertEquals(Optional.of("TIMER_IRQ_0"), Rp2040VectorTable.vectorName(16));
        assertEquals(Optional.of("PWM_IRQ_WRAP"), Rp2040VectorTable.irqName(4));
        assertEquals(Optional.of("PIO0_IRQ_0"), Rp2040VectorTable.irqName(7));
        assertEquals(Optional.of("PIO0_IRQ_1"), Rp2040VectorTable.irqName(8));
        assertEquals(Optional.of("PIO1_IRQ_0"), Rp2040VectorTable.irqName(9));
        assertEquals(Optional.of("PIO1_IRQ_1"), Rp2040VectorTable.irqName(10));
        assertEquals(Optional.of("DMA_IRQ_0"), Rp2040VectorTable.irqName(11));
        assertEquals(Optional.of("RTC_IRQ"), Rp2040VectorTable.irqName(25));
    }

    @Test
    void testRp2040AtomicAlias() {
        long uartBase = 0x40034000L;
        assertTrue(Rp2040AtomicAlias.isPeripheral(uartBase));
        assertFalse(Rp2040AtomicAlias.isAtomicAlias(uartBase));

        long xorAlias = Rp2040AtomicAlias.toAtomicAlias(uartBase, Rp2040AtomicAlias.Operation.XOR);
        assertEquals(0x50035000L, xorAlias);
        assertTrue(Rp2040AtomicAlias.isAtomicAlias(xorAlias));
        assertEquals(Rp2040AtomicAlias.Operation.XOR, Rp2040AtomicAlias.resolveOperation(xorAlias));
        assertEquals(uartBase, Rp2040AtomicAlias.toNormalAddress(xorAlias));

        long setAlias = Rp2040AtomicAlias.toAtomicAlias(uartBase, Rp2040AtomicAlias.Operation.SET);
        assertEquals(0x50036000L, setAlias);
        assertEquals(Rp2040AtomicAlias.Operation.SET, Rp2040AtomicAlias.resolveOperation(setAlias));
        assertEquals(uartBase, Rp2040AtomicAlias.toNormalAddress(setAlias));

        long clearAlias = Rp2040AtomicAlias.toAtomicAlias(uartBase, Rp2040AtomicAlias.Operation.CLEAR);
        assertEquals(0x50037000L, clearAlias);
        assertEquals(Rp2040AtomicAlias.Operation.CLEAR, Rp2040AtomicAlias.resolveOperation(clearAlias));
        assertEquals(uartBase, Rp2040AtomicAlias.toNormalAddress(clearAlias));
    }

    @Test
    void testRp2040Rom() {
        assertTrue(Rp2040Rom.containsAddress(0x00000000L));
        assertTrue(Rp2040Rom.containsAddress(0x00003FFFL));
        assertFalse(Rp2040Rom.containsAddress(0x00004000L));

        assertEquals(Optional.of("popcount32"), Rp2040Rom.functionName("P3"));
        assertEquals(Optional.of("memset"), Rp2040Rom.functionName("MS"));
        assertEquals(Optional.of("memcpy"), Rp2040Rom.functionName("MC"));
        assertEquals(Optional.of("flash_range_erase"), Rp2040Rom.functionName("RE"));
        assertEquals(Optional.of("flash_range_program"), Rp2040Rom.functionName("RP"));
    }

    @Test
    void testRp2040PioBlocks() {
        Rp2040TargetProvider provider = (Rp2040TargetProvider) resolver.resolvePart("RP2040").orElseThrow();
        List<RpPioBlock> pioBlocks = provider.pioBlocks();
        assertEquals(2, pioBlocks.size());

        RpPioBlock pio0 = pioBlocks.get(0);
        assertEquals(0, pio0.blockIndex());
        assertEquals(0x50200000L, pio0.baseAddress());
        assertEquals(4, pio0.stateMachineCount());
        assertEquals(32, pio0.instructionMemoryWords());
        assertEquals("PIO0", pio0.blockName());
        assertTrue(pio0.containsAddress(0x50200048L));

        RpPioBlock pio1 = pioBlocks.get(1);
        assertEquals(1, pio1.blockIndex());
        assertEquals(0x50300000L, pio1.baseAddress());
        assertEquals("PIO1", pio1.blockName());
    }
}
