package io.github.rezabakhshi.embedra.targets.stm32.mp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.BootRelationship;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.InterProcessorLink;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.SecurityDomainKind;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests for STM32MP heterogeneous target providers, boot chain, device tree, and security. */
class Stm32MpTargetProviderTest {

    @Test
    void registryResolvesFlagshipMp157Provider() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Optional<Stm32MpTargetProvider> provider = registry.findByExactPart("STM32MP157C");
        assertTrue(provider.isPresent());
        assertEquals("STM32MP157C", provider.get().exactPart());
        assertEquals("STM32MP157", provider.get().line());
        assertEquals("STM32MP1", provider.get().family());
        assertEquals("PLANNED", provider.get().supportState());
    }

    @Test
    void registryResolvesFlagshipMp257Provider() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Optional<Stm32MpTargetProvider> provider = registry.findByExactPart("STM32MP257F");
        assertTrue(provider.isPresent());
        assertEquals("STM32MP257F", provider.get().exactPart());
        assertEquals("STM32MP257", provider.get().line());
        assertEquals("STM32MP2", provider.get().family());
        assertEquals("PLANNED", provider.get().supportState());
    }

    @Test
    void registryResolvesSingleCoreMp135Provider() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Optional<Stm32MpTargetProvider> provider = registry.findByExactPart("STM32MP135F");
        assertTrue(provider.isPresent());
        assertEquals("STM32MP135F", provider.get().exactPart());
        assertEquals("STM32MP135", provider.get().line());
        assertEquals("STM32MP1", provider.get().family());
        assertEquals("PLANNED", provider.get().supportState());
    }

    @Test
    void registryFailsClosedOnUnknownOrMcuParts() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        assertFalse(registry.findByExactPart("STM32F103C8T6").isPresent());
        assertFalse(registry.findByExactPart("STM32WB55RGV6").isPresent());
        assertFalse(registry.findByExactPart("UNKNOWN_PART").isPresent());
        assertThrows(IllegalArgumentException.class, () -> registry.findByExactPart(""));
        assertThrows(NullPointerException.class, () -> registry.findByExactPart(null));
    }

    @Test
    void mp157TopologyModelsCortexA7AndCortexM4WithSeparatePrograms() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Stm32MpTargetProvider provider = registry.getRequired("STM32MP157CAA3");
        ExecutionTopology topology = provider.topology();

        assertEquals(ProgramStrategy.SEPARATE_PROGRAMS, topology.programStrategy());
        Set<String> nodeIds = topology.processorIds();
        assertTrue(nodeIds.containsAll(Set.of("ca7_0", "ca7_1", "cm4", "bootrom")));

        ProcessorNode ca7_0 = topology.processors().stream()
            .filter(p -> p.id().equals("ca7_0")).findFirst().orElseThrow();
        assertEquals(ProcessorKind.CPU_CORE, ca7_0.kind());
        assertEquals(Optional.of("ARMv7-A"), ca7_0.instructionSet());
        assertEquals(Optional.of("ARM:LE:32:v7"), ca7_0.ghidraLanguageId());
        assertEquals("APPLICATION", ca7_0.role());

        ProcessorNode cm4 = topology.processors().stream()
            .filter(p -> p.id().equals("cm4")).findFirst().orElseThrow();
        assertEquals(ProcessorKind.CPU_CORE, cm4.kind());
        assertEquals(Optional.of("ARMv7E-M"), cm4.instructionSet());
        assertEquals(Optional.of("ARM:LE:32:Cortex"), cm4.ghidraLanguageId());
        assertEquals("MICROCONTROLLER", cm4.role());

        List<InterProcessorLink> links = topology.communicationLinks();
        assertTrue(links.stream().anyMatch(l -> l.id().equals("ipcc_mailbox")
            && l.registerRange().isPresent()
            && l.registerRange().get().start() == 0x5C001000L));
        assertTrue(links.stream().anyMatch(l -> l.id().equals("hsem_semaphore")
            && l.registerRange().isPresent()
            && l.registerRange().get().start() == 0x5C000000L));

        List<SharedMemoryRegion> shared = topology.sharedMemories();
        assertTrue(shared.stream().anyMatch(m -> m.id().equals("sysram")
            && m.range().start() == 0x2FFC0000L && m.range().length() == 0x40000L));
        assertTrue(shared.stream().anyMatch(m -> m.id().equals("mcuram")
            && m.range().start() == 0x10000000L && m.range().length() == 0x60000L));
    }

    @Test
    void mp257TopologyModelsDualAArch64CortexA35AndCortexM33AndSmartRunCortexM0() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Stm32MpTargetProvider provider = registry.getRequired("STM32MP257FAI3");
        ExecutionTopology topology = provider.topology();

        assertEquals(ProgramStrategy.SEPARATE_PROGRAMS, topology.programStrategy());
        Set<String> nodeIds = topology.processorIds();
        assertTrue(nodeIds.containsAll(Set.of("ca35_0", "ca35_1", "cm33", "cm0p", "bootrom")));

        ProcessorNode ca35_0 = topology.processors().stream()
            .filter(p -> p.id().equals("ca35_0")).findFirst().orElseThrow();
        assertEquals(ProcessorKind.CPU_CORE, ca35_0.kind());
        assertEquals(Optional.of("AArch64"), ca35_0.instructionSet());
        assertEquals(Optional.of("AARCH64:LE:64:v8A"), ca35_0.ghidraLanguageId());

        ProcessorNode cm33 = topology.processors().stream()
            .filter(p -> p.id().equals("cm33")).findFirst().orElseThrow();
        assertEquals(ProcessorKind.CPU_CORE, cm33.kind());
        assertEquals(Optional.of("ARMv8-M"), cm33.instructionSet());
        assertEquals(Optional.of("ARM:LE:32:Cortex"), cm33.ghidraLanguageId());

        ProcessorNode cm0p = topology.processors().stream()
            .filter(p -> p.id().equals("cm0p")).findFirst().orElseThrow();
        assertEquals(ProcessorKind.CPU_CORE, cm0p.kind());
        assertEquals(Optional.of("ARMv6-M"), cm0p.instructionSet());
        assertEquals(Optional.of("ARM:LE:32:v6M"), cm0p.ghidraLanguageId());
    }

    @Test
    void mp135TopologyModelsSingleCortexA7WithoutCortexM() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Stm32MpTargetProvider provider = registry.getRequired("STM32MP135F");
        ExecutionTopology topology = provider.topology();

        Set<String> nodeIds = topology.processorIds();
        assertTrue(nodeIds.contains("ca7"));
        assertTrue(nodeIds.contains("bootrom"));
        assertFalse(nodeIds.contains("cm4"));
        assertFalse(nodeIds.contains("cm33"));
    }

    @Test
    void mp157BootChainCoversTfaBL2OpTeeUBootAndLinux() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Stm32MpTargetProvider provider = registry.getRequired("STM32MP157C");
        Stm32MpBootChainPlan bootChain = provider.bootChainPlan();

        assertEquals(Stm32MpBootChainPlan.BootArchitecture.A7_SECURE_BOOT, bootChain.architecture());
        List<Stm32MpBootChainPlan.BootStage> stages = bootChain.stages();
        assertFalse(stages.isEmpty());

        Stm32MpBootChainPlan.BootStage fsbl = stages.stream()
            .filter(s -> s.kind() == Stm32MpBootChainPlan.StageKind.FSBL).findFirst().orElseThrow();
        assertEquals("ca7_0", fsbl.executionUnitId());
        assertTrue(fsbl.artifactDescription().contains("TF-A BL2"));
        assertTrue(fsbl.executionRange().isPresent());
        assertEquals(0x2FFC0000L, fsbl.executionRange().get().start());

        Stm32MpBootChainPlan.BootStage ssbl = stages.stream()
            .filter(s -> s.kind() == Stm32MpBootChainPlan.StageKind.SSBL).findFirst().orElseThrow();
        assertTrue(ssbl.artifactDescription().contains("U-Boot"));

        Stm32MpBootChainPlan.BootStage coproc = stages.stream()
            .filter(s -> s.kind() == Stm32MpBootChainPlan.StageKind.COPROCESSOR_FIRMWARE)
            .findFirst().orElseThrow();
        assertEquals("cm4", coproc.executionUnitId());
        assertTrue(coproc.artifactDescription().contains("Cortex-M4"));
    }

    @Test
    void mp257BootChainSupportsSelectableFlavors() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Stm32MpTargetProvider provider = registry.getRequired("STM32MP257F");
        Stm32MpBootChainPlan a35Master = provider.bootChainPlan(
            Stm32MpBootChainPlan.BootArchitecture.A35_TRUSTED_DOMAIN);
        assertEquals(Stm32MpBootChainPlan.BootArchitecture.A35_TRUSTED_DOMAIN, a35Master.architecture());
        assertEquals("ca35_0", a35Master.stages().getFirst().executionUnitId());

        Stm32MpBootChainPlan m33Master = provider.bootChainPlan(
            Stm32MpBootChainPlan.BootArchitecture.M33_TRUSTED_DOMAIN);
        assertEquals(Stm32MpBootChainPlan.BootArchitecture.M33_TRUSTED_DOMAIN, m33Master.architecture());
        assertEquals("cm33", m33Master.stages().getFirst().executionUnitId());
    }

    @Test
    void mp157DeviceTreePlanModelsRemoteprocMailboxesAndReservedMemory() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Stm32MpTargetProvider provider = registry.getRequired("STM32MP157C");
        Stm32MpDeviceTreePlan dt = provider.deviceTreePlan();

        assertEquals("(GPL-2.0+ OR BSD-3-Clause)", dt.license());
        assertTrue(dt.dtsSource().contains("stm32mp157c.dtsi"));

        Stm32MpDeviceTreePlan.RemoteProcNode rproc = dt.remoteProcNodes().getFirst();
        assertEquals("m4_rproc", rproc.nodeName());
        assertEquals("cm4", rproc.coreId());
        assertTrue(rproc.reservedMemoryRegions().containsAll(
            List.of("retram", "mcuram", "mcuram2", "vdev0vring0", "vdev0vring1", "vdev0buffer")));

        Stm32MpDeviceTreePlan.MailboxBinding ipcc = dt.mailboxControllers().getFirst();
        assertEquals("ipcc", ipcc.nodeName());
        assertEquals(0x5C001000L, ipcc.registerRange().start());
        assertEquals(2, ipcc.numChannels());

        Stm32MpDeviceTreePlan.SemaphoreBinding hsem = dt.semaphoreControllers().getFirst();
        assertEquals("hsem", hsem.nodeName());
        assertEquals(0x5C000000L, hsem.registerRange().start());
        assertEquals(32, hsem.numSemaphores());
    }

    @Test
    void mp157SecurityPlanModelsTrustZoneAndEtzpc() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Stm32MpTargetProvider provider = registry.getRequired("STM32MP157C");
        Stm32MpSecurityPlan sec = provider.securityPlan();

        assertEquals(Stm32MpSecurityPlan.SecurityArchitecture.ETZPC_TRUSTZONE, sec.architecture());
        assertTrue(sec.domains().stream().anyMatch(d -> d.kind() == SecurityDomainKind.SECURE));
        assertTrue(sec.domains().stream().anyMatch(d -> d.kind() == SecurityDomainKind.NON_SECURE));
        assertTrue(sec.firewallWindows().stream().anyMatch(f -> f.controllerName().equals("ETZPC")
            && f.range().start() == 0x5C007000L));
        assertTrue(sec.otpRegions().stream().anyMatch(o -> o.controllerName().equals("BSEC")
            && o.range().start() == 0x5C005000L));
    }

    @Test
    void mp157WorkspacePlanAssignsSeparateGhidraProgramsPerDomain() {
        Stm32MpProviderRegistry registry = Stm32MpProviderRegistry.instance();
        Stm32MpTargetProvider provider = registry.getRequired("STM32MP157C");
        Stm32MpWorkspacePlan ws = provider.workspacePlan();

        assertEquals(3, ws.programSlots().size());
        Stm32MpWorkspacePlan.ProgramSlot linux = ws.programSlots().stream()
            .filter(s -> s.id().equals("ca7-linux-program")).findFirst().orElseThrow();
        assertEquals("ARM:LE:32:v7", linux.ghidraLanguageId());
        assertEquals(SecurityDomainKind.NON_SECURE, linux.securityDomain().kind());

        Stm32MpWorkspacePlan.ProgramSlot secure = ws.programSlots().stream()
            .filter(s -> s.id().equals("ca7-secure-program")).findFirst().orElseThrow();
        assertEquals("ARM:LE:32:v7", secure.ghidraLanguageId());
        assertEquals(SecurityDomainKind.SECURE, secure.securityDomain().kind());

        Stm32MpWorkspacePlan.ProgramSlot m4 = ws.programSlots().stream()
            .filter(s -> s.id().equals("cm4-firmware-program")).findFirst().orElseThrow();
        assertEquals("ARM:LE:32:Cortex", m4.ghidraLanguageId());

        List<Stm32MpWorkspacePlan.CrossProgramReference> refs = ws.crossProgramReferences();
        assertTrue(refs.stream().anyMatch(r -> r.kind() == Stm32MpWorkspacePlan.ReferenceKind.BOOT_HANDOFF
            && r.sourceSlotId().equals("ca7-secure-program") && r.targetSlotId().equals("ca7-linux-program")));
        assertTrue(refs.stream().anyMatch(r -> r.kind() == Stm32MpWorkspacePlan.ReferenceKind.SHARED_MAILBOX
            && r.sharedRange().isPresent() && r.sharedRange().get().start() == 0x5C001000L));
    }

    @Test
    void deviceTreeParserParsesDtsExcerptUnderLimits() throws Exception {
        String dts = """
            /dts-v1/;
            / {
                reserved-memory {
                    #address-cells = <1>;
                    #size-cells = <1>;
                    mcuram: mcuram@30000000 {
                        reg = <0x30000000 0x20000>;
                        no-map;
                    };
                    retram: retram@38000000 {
                        reg = <0x38000000 0x10000>;
                        no-map;
                    };
                };
                soc {
                    ipcc: mailbox@5c001000 {
                        reg = <0x5c001000 0x400>;
                        #mbox-cells = <1>;
                    };
                    hsem: hwspinlock@5c000000 {
                        reg = <0x5c000000 0x400>;
                        #hwlock-cells = <1>;
                    };
                    m4_rproc: m4@0 {
                        memory-region = <&retram>, <&mcuram>;
                        mboxes = <&ipcc 0>, <&ipcc 1>;
                        mbox-names = "vq0", "vq1";
                        hwlocks = <&hsem 0>;
                    };
                };
            };
            """;

        Stm32MpDeviceTreePlan parsed = Stm32MpDeviceTreeParser.parse("STM32MP157C", dts,
            ParserLimits.defaults(), CancellationToken.none());
        assertNotNull(parsed);
        assertEquals(1, parsed.remoteProcNodes().size());
        assertEquals("m4_rproc", parsed.remoteProcNodes().getFirst().nodeName());
        assertEquals(List.of("retram", "mcuram"), parsed.remoteProcNodes().getFirst().reservedMemoryRegions());
        assertEquals(2, parsed.reservedMemoryNodes().size());
        assertEquals(1, parsed.mailboxControllers().size());
        assertEquals(1, parsed.semaphoreControllers().size());
    }

    @Test
    void deviceTreeParserRejectsOversizedOrCancelledInput() {
        ParserLimits limits = new ParserLimits(100, 100, 100, 10, 5, java.time.Duration.ofSeconds(1));
        assertThrows(Exception.class, () ->
            Stm32MpDeviceTreeParser.parse("STM32MP157C", "a".repeat(150), limits, CancellationToken.none()));

        CancellationToken cancelled = () -> true;
        assertThrows(Exception.class, () ->
            Stm32MpDeviceTreeParser.parse("STM32MP157C", "/dts-v1/;", ParserLimits.defaults(), cancelled));
    }
}
