package io.github.rezabakhshi.embedra.targets.stm32.memory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.model.CommunicationKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner.BootMode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Stm32MemoryPlannerTest {
    private static final Path CATALOG = Path.of("catalogs/stm32/2026-09-29/memory-plans.json");

    @TempDir
    Path temporary;

    @Test
    void exactCapacityAndSpecialRegionsDoNotInheritTheHeaderMaximum() throws Exception {
        var planner = load(CATALOG);
        for (String part : new String[] {"STM32F103C8T6", "STM32F103CBT6", "STM32F103RBT6"}) {
            var plan = planner.plan(part, BootMode.UNKNOWN);
            long flashBytes = part.equals("STM32F103C8T6") ? 65536 : 131072;
            assertEquals(0x08000000L + flashBytes, plan.regions().get(0).range().endExclusive());
            assertEquals(20480, plan.regions().get(1).range().length());
            assertEquals(0x1ffff000L, plan.regions().get(2).range().start());
            assertEquals(2048, plan.regions().get(2).range().length());
            assertEquals(0x1ffff800L, plan.regions().get(3).range().start());
            assertEquals(16, plan.regions().get(3).range().length());
            assertEquals("UNAVAILABLE", plan.otpAvailability());
            assertTrue(plan.otpReason().contains("258 x 64"));
            assertEquals("PLANNED", plan.supportState());
            assertThrows(UnsupportedOperationException.class, () -> plan.regions().clear());
        }
    }

    @Test
    void bootViewsRequireAnExplicitConfigurationAndSramHasNoZeroAlias() throws Exception {
        var planner = load(CATALOG);
        var unknown = planner.plan("STM32F103C8T6", BootMode.UNKNOWN);
        assertTrue(unknown.aliases().isEmpty());
        assertEquals(2, unknown.unresolvedBootAliases().size());
        var flash = planner.plan("STM32F103C8T6", BootMode.MAIN_FLASH);
        assertEquals("FLASH", flash.aliases().getFirst().target());
        assertEquals(65536, flash.aliases().getFirst().range().length());
        var system = planner.plan("STM32F103C8T6", BootMode.SYSTEM_MEMORY);
        assertEquals("SYSTEM", system.aliases().getFirst().target());
        assertEquals(2048, system.aliases().getFirst().range().length());
        var sram = planner.plan("STM32F103C8T6", BootMode.SRAM);
        assertTrue(sram.aliases().isEmpty());
        assertTrue(sram.unresolvedBootAliases().isEmpty());
        assertEquals(0x20000000L, sram.regions().get(1).range().start());
    }

    @Test
    void bitBandTranslationUsesOnlyBackedSramAndAlignedWords() throws Exception {
        var view = load(CATALOG).plan("STM32F103C8T6", BootMode.UNKNOWN).bitBandViews().getFirst();
        assertEquals(new Stm32MemoryPlanner.BitReference(0x20000300L, 2), view.translate(0x22006008L));
        assertEquals(new Stm32MemoryPlanner.BitReference(0x20004fffL, 7),
            view.translate(view.range().endExclusive() - 4));
        assertThrows(IllegalArgumentException.class, () -> view.translate(0x22006009L));
        assertThrows(IllegalArgumentException.class, () -> view.translate(view.range().endExclusive()));
        assertThrows(IllegalArgumentException.class, () -> view.translate(0x21ffffffL));
    }

    @Test
    void bootRomIsAnAlternativeContextOnOnePhysicalCoreAndResetHandlerStaysUnknown() throws Exception {
        var plan = load(CATALOG).plan("STM32F103C8T6", BootMode.UNKNOWN);
        assertEquals(1, plan.topology().processors().stream()
            .filter(node -> node.kind() == ProcessorKind.CPU_CORE).count());
        assertEquals(1, plan.topology().processors().stream()
            .filter(node -> node.kind() == ProcessorKind.BOOT_ROM).count());
        assertEquals(ProgramStrategy.SHARED_PROGRAM, plan.topology().programStrategy());
        assertTrue(plan.topology().processors().stream().allMatch(node -> node.resetEntries().isEmpty()));
        assertEquals("UNKNOWN_UNTIL_VECTOR_BYTES_ARE_SUPPLIED", plan.resetHandlerAvailability());
        assertEquals(plan.topology().processors().get(0).ghidraLanguageId(),
            plan.topology().processors().get(1).ghidraLanguageId());
    }

    @Test
    void incompleteAndNonexactIdentitiesFailClosed() throws Exception {
        var planner = load(CATALOG);
        assertThrows(IllegalArgumentException.class, () -> planner.plan("STM32F103", BootMode.UNKNOWN));
        assertThrows(IllegalArgumentException.class, () -> planner.plan("stm32f103c8t6", BootMode.UNKNOWN));
        assertThrows(IllegalArgumentException.class, () -> planner.plan("STM32N657X0H4Q", BootMode.UNKNOWN));
    }

    @Test
    void romlessN6KeepsItsRamAndBootRomButDeclaresNoFlash() throws Exception {
        var plan = load(CATALOG).plan("STM32N657X0H3Q", BootMode.UNKNOWN);
        assertTrue(plan.regions().stream().noneMatch(r -> r.kind().equals("FLASH")));
        assertEquals(4200 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        assertEquals(1, plan.regions().stream().filter(r -> r.kind().equals("SYSTEM")).count());
        assertTrue(plan.bitBandViews().isEmpty());
    }

    @Test
    void g491CountsPhysicalBanksOnceAndPreservesTheCcmSystemView() throws Exception {
        var plan = load(CATALOG).plan("STM32G491RET6", BootMode.UNKNOWN);
        assertEquals(112 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        assertEquals(1, plan.aliases().size());
        assertEquals("CCM", plan.aliases().getFirst().target());
        assertEquals(0x20018000L, plan.aliases().getFirst().range().start());
        assertEquals(3, plan.unresolvedBootAliases().size());
        assertEquals(512 * 1024, plan.regions().getFirst().range().length());
        assertEquals("AVAILABLE", plan.otpAvailability());
        var ccmBitBand = plan.bitBandViews().stream().filter(v -> v.id().equals("CCM_BIT_BAND"))
            .findFirst().orElseThrow();
        assertEquals(new Stm32MemoryPlanner.BitReference(0x10000000L, 2),
            ccmBitBand.translate(0x22300008L));
        var sramBoot = load(CATALOG).plan("STM32G491RET6", BootMode.SRAM);
        assertEquals("SRAM1", sramBoot.aliases().getLast().target());
        assertEquals(80 * 1024, sramBoot.aliases().getLast().range().length());
    }

    @Test
    void g431DoesNotInheritTheLargerG4BankOrSystemLayout() throws Exception {
        var plan = load(CATALOG).plan("STM32G431RBT6", BootMode.UNKNOWN);
        assertEquals(32 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        assertEquals(128 * 1024, plan.regions().getFirst().range().length());
        assertEquals(0x20005800L, plan.aliases().getFirst().range().start());
        var ccm = plan.bitBandViews().getLast();
        assertEquals(new Stm32MemoryPlanner.BitReference(0x100027ffL, 7),
            ccm.translate(ccm.range().endExclusive() - 4));
        assertThrows(IllegalArgumentException.class, () -> ccm.translate(ccm.range().endExclusive()));
        assertEquals(1, plan.regions().stream().filter(r -> r.kind().equals("SYSTEM")).count());
        assertEquals(28 * 1024, plan.regions().stream().filter(r -> r.kind().equals("SYSTEM"))
            .findFirst().orElseThrow().range().length());
        assertEquals(48, plan.regions().stream().filter(r -> r.kind().equals("OPTION"))
            .findFirst().orElseThrow().range().length());
        assertEquals(1024, plan.regions().stream().filter(r -> r.kind().equals("OTP"))
            .findFirst().orElseThrow().range().length());
    }

    @Test
    void f207CountsBackupSramOnceAndBitBandsEachPhysicalBank() throws Exception {
        var planner = load(CATALOG);
        var plan = planner.plan("STM32F207ZGT6", BootMode.UNKNOWN);
        assertEquals(132 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        assertEquals(7, plan.regions().size());
        var sram1 = plan.bitBandViews().stream().filter(v -> v.id().equals("SRAM1_BIT_BAND"))
            .findFirst().orElseThrow();
        assertEquals(0x22000000L, sram1.range().start());
        assertEquals(0x1C000L * 32, sram1.range().length());
        var backup = plan.bitBandViews().stream().filter(v -> v.id().equals("BACKUP_SRAM_BIT_BAND"))
            .findFirst().orElseThrow();
        assertEquals(0x42480000L, backup.range().start());
        assertEquals(new Stm32MemoryPlanner.BitReference(0x40024008L, 2), backup.translate(0x42480108L));
        assertEquals(3, plan.unresolvedBootAliases().size());
        var sramBoot = planner.plan("STM32F207ZGT6", BootMode.SRAM);
        assertEquals("SRAM1", sramBoot.aliases().getLast().target());
        assertEquals(0x1C000L, sramBoot.aliases().getLast().range().length());
        assertEquals(0x7800L, plan.regions().stream().filter(r -> r.kind().equals("SYSTEM"))
            .findFirst().orElseThrow().range().length());
        assertEquals(0x210L, plan.regions().stream().filter(r -> r.kind().equals("OTP"))
            .findFirst().orElseThrow().range().length());
        assertEquals("AVAILABLE", plan.otpAvailability());
    }

    @Test
    void f401KeepsItsExactSingleBankAndThreeBootViews() throws Exception {
        var planner = load(CATALOG);
        var plan = planner.plan("STM32F401RET6", BootMode.UNKNOWN);
        assertEquals(96 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        assertEquals(512 * 1024, plan.regions().stream().filter(r -> r.kind().equals("FLASH"))
            .findFirst().orElseThrow().range().length());
        assertEquals(0x18000L * 32, plan.bitBandViews().getFirst().range().length());
        assertEquals(new Stm32MemoryPlanner.BitReference(0x20000300L, 2),
            plan.bitBandViews().getFirst().translate(0x22006008L));
        assertEquals(3, plan.unresolvedBootAliases().size());
        assertEquals(0x1FFFC000L, plan.regions().stream().filter(r -> r.kind().equals("OPTION"))
            .findFirst().orElseThrow().range().start());
        assertEquals(0x210L, plan.regions().stream().filter(r -> r.kind().equals("OTP"))
            .findFirst().orElseThrow().range().length());
        var systemBoot = planner.plan("STM32F401RET6", BootMode.SYSTEM_MEMORY);
        assertEquals("SYSTEM", systemBoot.aliases().getFirst().target());
        assertEquals(0x7800L, systemBoot.aliases().getFirst().range().length());
    }

    @Test
    void f756SharesOneFlashAndHasNoBitBandOrFixedBootAlias() throws Exception {
        var plan = load(CATALOG).plan("STM32F756ZGT6", BootMode.UNKNOWN);
        assertEquals(340 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        assertTrue(plan.bitBandViews().isEmpty());
        assertEquals(1, plan.aliases().size());
        assertEquals("FLASH", plan.aliases().getFirst().target());
        assertEquals(0x00200000L, plan.aliases().getFirst().range().start());
        assertTrue(plan.unresolvedBootAliases().isEmpty());
        assertEquals(0, plan.regions().stream().filter(r -> r.id().equals("ITCM_RAM"))
            .findFirst().orElseThrow().range().start());
        assertEquals(0x1FF0EDC0L, plan.regions().stream().filter(r -> r.kind().equals("SYSTEM"))
            .findFirst().orElseThrow().range().endExclusive());
        assertEquals(0x420L, plan.regions().stream().filter(r -> r.kind().equals("OTP"))
            .findFirst().orElseThrow().range().length());
        assertEquals(32, plan.regions().stream().filter(r -> r.kind().equals("OPTION"))
            .findFirst().orElseThrow().range().length());
        assertTrue(plan.otpReason().contains("1024"));
        assertEquals("AVAILABLE", plan.otpAvailability());
    }

    @Test
    void g473Category3KeepsItsOwnBanksAndTwoInformationBlocks() throws Exception {
        var plan = load(CATALOG).plan("STM32G473QET6", BootMode.UNKNOWN);
        assertEquals(128 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        assertEquals(512 * 1024, plan.regions().stream().filter(r -> r.kind().equals("FLASH"))
            .findFirst().orElseThrow().range().length());
        assertEquals(0x20018000L, plan.aliases().getFirst().range().start());
        var ccm = plan.bitBandViews().stream().filter(v -> v.id().equals("CCM_BIT_BAND"))
            .findFirst().orElseThrow();
        assertEquals(0x22300000L, ccm.range().start());
        assertEquals(2, plan.regions().stream().filter(r -> r.kind().equals("SYSTEM")).count());
        assertEquals(2, plan.regions().stream().filter(r -> r.kind().equals("OPTION")).count());
        assertEquals(48, plan.regions().stream().filter(r -> r.kind().equals("OPTION"))
            .findFirst().orElseThrow().range().length());
        assertEquals(1024, plan.regions().stream().filter(r -> r.kind().equals("OTP"))
            .findFirst().orElseThrow().range().length());
    }

    @Test
    void wb55IsDualCoreSharingSramWithoutDuplicatingPhysicalRam() throws Exception {
        var plan = load(CATALOG).plan("STM32WB55RGV6", BootMode.UNKNOWN);
        var topology = plan.topology();
        assertEquals(2, topology.processors().stream()
            .filter(node -> node.kind() == ProcessorKind.CPU_CORE).count());
        assertEquals(1, topology.processors().stream()
            .filter(node -> node.kind() == ProcessorKind.BOOT_ROM).count());
        var cpu1 = topology.processors().get(0);
        var cpu2 = topology.processors().get(1);
        assertEquals("Application Cortex-M4", cpu1.role());
        assertEquals("Network Cortex-M0+", cpu2.role());
        assertEquals("ARMv7E-M Thumb little-endian", cpu1.instructionSet().orElseThrow());
        assertEquals("ARMv6-M Thumb little-endian", cpu2.instructionSet().orElseThrow());
        assertEquals(ProgramStrategy.SHARED_PROGRAM, topology.programStrategy());
        assertEquals(3, topology.sharedMemories().size());
        assertEquals(256 * 1024, topology.sharedMemories().stream()
            .mapToLong(region -> region.range().length()).sum());
        assertEquals(Set.of(cpu1.id(), cpu2.id()), topology.sharedMemories().getFirst()
            .referencedProcessorIds());
        assertEquals(1, topology.bootRelationships().stream()
            .filter(relation -> relation.targetNodeId().equals("cpu2")).count());
        assertEquals(2, topology.communicationLinks().size());
        assertTrue(topology.communicationLinks().stream().anyMatch(
            link -> link.kind() == CommunicationKind.MAILBOX));
        assertTrue(topology.communicationLinks().stream().anyMatch(
            link -> link.kind() == CommunicationKind.HARDWARE_SEMAPHORE));
        long physicalRam = plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum();
        assertEquals(256 * 1024, physicalRam);
        assertEquals(2, plan.aliases().size());
        assertTrue(plan.aliases().stream().allMatch(alias -> alias.condition().equals("ALWAYS")));
        assertTrue(plan.aliases().stream().anyMatch(alias -> alias.range().start() == 0x10000000L));
        plan.bitBandViews().forEach(view -> assertEquals(view.target().length() * 32, view.range().length()));
        assertEquals("UNKNOWN_UNTIL_VECTOR_BYTES_ARE_SUPPLIED", plan.resetHandlerAvailability());
    }

    @Test
    void wb55DoesNotOverclaimCpu1WriteAccessToCpu2SecureSram2() throws Exception {
        var topology = load(CATALOG).plan("STM32WB55RGV6", BootMode.UNKNOWN).topology();
        var sram1 = topology.sharedMemories().stream()
            .filter(memory -> memory.id().equals("SRAM1-shared")).findFirst().orElseThrow();
        assertEquals(Set.of("cpu1", "cpu2"), sram1.readerNodeIds());
        assertEquals(Set.of("cpu1", "cpu2"), sram1.writerNodeIds());
        for (String bank : new String[] {"SRAM2A-shared", "SRAM2B-shared"}) {
            var memory = topology.sharedMemories().stream()
                .filter(region -> region.id().equals(bank)).findFirst().orElseThrow();
            assertEquals(Set.of("cpu2"), memory.readerNodeIds());
            assertEquals(Set.of("cpu2"), memory.writerNodeIds());
            assertTrue(!memory.writerNodeIds().contains("cpu1"));
        }
    }

    @Test
    void wb15HasTwoPhysicalCoresNotOne() throws Exception {
        var plan = load(CATALOG).plan("STM32WB15CCU6", BootMode.UNKNOWN);
        var topology = plan.topology();
        assertEquals(2, topology.processors().stream()
            .filter(node -> node.kind() == ProcessorKind.CPU_CORE).count());
        assertEquals("Network Cortex-M0+", topology.processors().get(1).role());
        assertEquals(2, topology.communicationLinks().size());
        assertTrue(topology.communicationLinks().stream().anyMatch(
            link -> link.kind() == CommunicationKind.MAILBOX));
        assertTrue(topology.communicationLinks().stream().anyMatch(
            link -> link.kind() == CommunicationKind.HARDWARE_SEMAPHORE));
        assertEquals(1, topology.bootRelationships().stream()
            .filter(relation -> relation.targetNodeId().equals("cpu2")).count());
        assertEquals(48 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        var sram2a = topology.sharedMemories().stream()
            .filter(memory -> memory.id().equals("SRAM2A-shared")).findFirst().orElseThrow();
        assertEquals(Set.of("cpu2"), sram2a.writerNodeIds());
    }

    @Test
    void h735SharedRamRequiresAndResolvesAnExplicitAllocation() throws Exception {
        var planner = load(CATALOG);
        var unresolved = planner.plan("STM32H735IGK6", BootMode.UNKNOWN);
        assertEquals(1, unresolved.unresolvedConfigurationRegions().size());
        assertEquals("ITCM_AXI_SHARED", unresolved.unresolvedConfigurationRegions().getFirst().id());
        Stm32MemoryPlanner.Region placeholder =
            unresolved.unresolvedConfigurationRegions().getFirst();
        assertEquals(192 * 1024, placeholder.range().length());
        assertTrue(placeholder.range().start() + placeholder.range().length() <= 0x24020000L);
        assertEquals(372 * 1024, unresolved.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());

        record Allocation(String id, long itcmShared, long axiShared) {
        }

        var allocations = Map.of(
            "ITCM_AXI_SHARED_64_320", new Allocation("ITCM_AXI_SHARED_64_320", 0, 0x30000),
            "ITCM_AXI_SHARED_128_256", new Allocation("ITCM_AXI_SHARED_128_256", 0x10000, 0x20000),
            "ITCM_AXI_SHARED_192_192", new Allocation("ITCM_AXI_SHARED_192_192", 0x20000, 0x10000),
            "ITCM_AXI_SHARED_256_128", new Allocation("ITCM_AXI_SHARED_256_128", 0x30000, 0));
        for (var entry : allocations.entrySet()) {
            var plan = planner.plan("STM32H735IGK6", BootMode.UNKNOWN,
                Map.of("ITCM_AXI_SHARED", entry.getKey()));
            assertTrue(plan.unresolvedConfigurationRegions().isEmpty());
            long itcmShared = plan.regions().stream().filter(r -> r.range().start() >= 0x00010000
                && r.range().start() < 0x00040000).mapToLong(r -> r.range().length()).sum();
            long axiShared = plan.regions().stream().filter(r -> r.range().start() >= 0x24020000
                && r.range().start() < 0x24050000).mapToLong(r -> r.range().length()).sum();
            assertEquals(entry.getValue().itcmShared(), itcmShared, entry.getKey());
            assertEquals(entry.getValue().axiShared(), axiShared, entry.getKey());
            assertEquals(564 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
                .mapToLong(r -> r.range().length()).sum(), entry.getKey());
        }
        assertThrows(IllegalArgumentException.class, () -> planner.plan("STM32H735IGK6",
            BootMode.UNKNOWN, Map.of("ITCM_AXI_SHARED", "NOT_A_DECLARED_ALLOCATION")));
        assertThrows(IllegalArgumentException.class, () -> planner.plan("STM32H735IGK6",
            BootMode.UNKNOWN, Map.of("UNKNOWN_CONFIG", "ITCM_AXI_SHARED_64_320")));
    }

    @Test
    void changedCatalogIsRejectedBeforePlanning() throws Exception {
        Path changed = temporary.resolve("changed.json");
        Files.writeString(changed, Files.readString(CATALOG).replace("65536", "131072"));
        assertThrows(IOException.class, () -> load(changed));
    }

    private static Stm32MemoryPlanner load(Path path) throws Exception {
        var limits = ParserLimits.defaults();
        var ids = Stm32CuratedPartIds.load(Path.of("catalogs/stm32/2026-09-29/selection.json"),
            limits, CancellationToken.none());
        return Stm32MemoryPlanner.load(path, ids, limits, CancellationToken.none());
    }
}
