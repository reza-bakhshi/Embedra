package io.github.rezabakhshi.embedra.core.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ExecutionTopologyTest {
    private static final Evidence DOCUMENTED = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD, "synthetic topology fixture", "documented relation");

    @Test
    void representsSingleCoreAndFixedFunctionUnitsWithoutConflatingThem() {
        ProcessorNode cpu = executableNode("cpu0", ProcessorKind.CPU_CORE, "Xtensa LX7",
            SecurityDomain.unknown(), FirmwareSource.SHARED_IMAGE);
        ProcessorNode crypto = new ProcessorNode("aes", ProcessorKind.FIXED_FUNCTION_ACCELERATOR,
            Optional.empty(), Optional.empty(), Optional.empty(), "AES accelerator",
            SecurityDomain.unknown(), "soc", Set.of("peripheral"), List.of(),
            FirmwareSource.NOT_APPLICABLE, Confidence.VERIFIED, List.of(DOCUMENTED));

        ExecutionTopology topology = new ExecutionTopology(List.of(cpu, crypto), List.of(), List.of(),
            List.of(), List.of(), ProgramStrategy.SHARED_PROGRAM);

        assertEquals(2, topology.processors().size());
        assertTrue(cpu.kind().executesRecoverableInstructions());
        assertFalse(crypto.kind().executesRecoverableInstructions());
        assertEquals(ProgramStrategy.SHARED_PROGRAM, topology.programStrategy());
    }

    @Test
    void representsSymmetricCoresSharedMemoryBootAndCommunication() {
        ProcessorNode cpu0 = executableNode("cpu0", ProcessorKind.CPU_CORE, "ARMv6-M",
            SecurityDomain.nonSecure(), FirmwareSource.SHARED_IMAGE);
        ProcessorNode cpu1 = executableNode("cpu1", ProcessorKind.CPU_CORE, "ARMv6-M",
            SecurityDomain.nonSecure(), FirmwareSource.SHARED_IMAGE);
        SharedMemoryRegion sram = new SharedMemoryRegion("sram",
            new AddressRange("cpu", 0x2000_0000L, 0x40000), Set.of("cpu0", "cpu1"),
            Set.of("cpu0", "cpu1"), Set.of("cpu0", "cpu1"),
            List.of(new AddressRange("cpu-alias", 0, 0x40000)), Confidence.VERIFIED,
            List.of(DOCUMENTED));
        BootRelationship boot = new BootRelationship("core1-launch", "cpu0", "cpu1",
            BootRelationshipType.RELEASES_FROM_RESET, "FIFO launch sequence",
            Confidence.DERIVED, List.of(DOCUMENTED));
        InterProcessorLink fifo = new InterProcessorLink("sio-fifo", CommunicationKind.FIFO,
            Set.of("cpu0", "cpu1"), Optional.of(new AddressRange("peripheral", 0xd0000050L, 8)),
            Confidence.VERIFIED, List.of(DOCUMENTED));
        ProcessorGroup symmetric = new ProcessorGroup("application-cores",
            ProcessorGroupKind.SYMMETRIC, Set.of("cpu0", "cpu1"));

        ExecutionTopology topology = new ExecutionTopology(List.of(cpu0, cpu1), List.of(sram),
            List.of(boot), List.of(fifo), List.of(symmetric), ProgramStrategy.SHARED_PROGRAM);

        assertEquals(Set.of("cpu0", "cpu1"), topology.processorIds());
        assertEquals(1, topology.sharedMemories().size());
        assertEquals(1, topology.bootRelationships().size());
        assertEquals(1, topology.communicationLinks().size());
        assertEquals(1, topology.processorGroups().size());
    }

    @Test
    void representsAlternativeArchitecturesAndSecurityDomains() {
        ProcessorNode secureArm = executableNode("arm-secure", ProcessorKind.CPU_CORE, "ARMv8-M",
            SecurityDomain.secure(), FirmwareSource.INDEPENDENT_IMAGE);
        ProcessorNode nonSecureArm = executableNode("arm-nonsecure", ProcessorKind.CPU_CORE, "ARMv8-M",
            SecurityDomain.nonSecure(), FirmwareSource.INDEPENDENT_IMAGE);
        ProcessorNode riscV = executableNode("riscv", ProcessorKind.CPU_CORE, "Hazard3",
            SecurityDomain.unknown(), FirmwareSource.INDEPENDENT_IMAGE);
        ProcessorGroup alternatives = new ProcessorGroup("boot-architecture",
            ProcessorGroupKind.ALTERNATIVE_BOOT, Set.of("arm-secure", "riscv"));

        ExecutionTopology topology = new ExecutionTopology(
            List.of(secureArm, nonSecureArm, riscV), List.of(), List.of(), List.of(),
            List.of(alternatives), ProgramStrategy.SEPARATE_PROGRAMS);

        assertEquals(SecurityDomainKind.SECURE, secureArm.securityDomain().kind());
        assertEquals(SecurityDomainKind.NON_SECURE, nonSecureArm.securityDomain().kind());
        assertEquals(ProgramStrategy.SEPARATE_PROGRAMS, topology.programStrategy());
    }

    @Test
    void rejectsContradictoryProcessorMetadata() {
        assertThrows(IllegalArgumentException.class, () -> new ProcessorNode(
            "cpu", ProcessorKind.CPU_CORE, Optional.empty(), Optional.empty(), Optional.empty(),
            "application", SecurityDomain.unknown(), "soc", Set.of("cpu"), List.of(),
            FirmwareSource.SHARED_IMAGE, Confidence.UNKNOWN, List.of(DOCUMENTED)));
        assertThrows(IllegalArgumentException.class, () -> new ProcessorNode(
            "dma", ProcessorKind.DMA_BUS_MASTER, Optional.of("ARM"), Optional.empty(), Optional.empty(),
            "DMA", SecurityDomain.unknown(), "soc", Set.of("bus"), List.of(),
            FirmwareSource.NOT_APPLICABLE, Confidence.VERIFIED, List.of(DOCUMENTED)));
        assertThrows(IllegalArgumentException.class, () -> processorWithFields(
            "", Optional.of("ARM"), Optional.of("language"), Optional.of("default"),
            "role", "owner", Set.of("cpu")));
        assertThrows(IllegalArgumentException.class, () -> processorWithFields(
            "cpu", Optional.of("ARM"), Optional.of("language"), Optional.of("default"),
            "", "owner", Set.of("cpu")));
        assertThrows(IllegalArgumentException.class, () -> processorWithFields(
            "cpu", Optional.of("ARM"), Optional.of("language"), Optional.of("default"),
            "role", "", Set.of("cpu")));
        assertThrows(IllegalArgumentException.class, () -> processorWithFields(
            "cpu", Optional.of(" "), Optional.of("language"), Optional.of("default"),
            "role", "owner", Set.of("cpu")));
        assertThrows(IllegalArgumentException.class, () -> processorWithFields(
            "cpu", Optional.of("ARM"), Optional.of(" "), Optional.of("default"),
            "role", "owner", Set.of("cpu")));
        assertThrows(IllegalArgumentException.class, () -> processorWithFields(
            "cpu", Optional.of("ARM"), Optional.of("language"), Optional.of(" "),
            "role", "owner", Set.of("cpu")));
        assertThrows(IllegalArgumentException.class, () -> processorWithFields(
            "cpu", Optional.of("ARM"), Optional.empty(), Optional.of("default"),
            "role", "owner", Set.of("cpu")));
        assertThrows(IllegalArgumentException.class, () -> processorWithFields(
            "cpu", Optional.of("ARM"), Optional.of("language"), Optional.of("default"),
            "role", "owner", Set.of(" ")));
    }

    @Test
    void rejectsInvalidRelationshipValueObjects() {
        assertThrows(IllegalArgumentException.class,
            () -> new SecurityDomain(" ", SecurityDomainKind.CUSTOM));
        assertThrows(IllegalArgumentException.class, () -> new ResetEntry(
            "", "cpu", 0, Confidence.UNKNOWN, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new ResetEntry(
            "reset", "", 0, Confidence.UNKNOWN, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new ResetEntry(
            "reset", "cpu", -1, Confidence.UNKNOWN, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new SharedMemoryRegion(
            "", new AddressRange("cpu", 0, 4), Set.of(), Set.of(), Set.of(), List.of(),
            Confidence.UNKNOWN, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new SharedMemoryRegion(
            "memory", new AddressRange("cpu", 0, 4), Set.of(), Set.of(), Set.of(),
            List.of(new AddressRange("alias", 0, 2)), Confidence.UNKNOWN, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new ProcessorGroup(
            "", ProcessorGroupKind.SYMMETRIC, Set.of("a", "b")));
        assertThrows(IllegalArgumentException.class, () -> new ProcessorGroup(
            "group", ProcessorGroupKind.SYMMETRIC, Set.of("a")));
        assertThrows(IllegalArgumentException.class, () -> new InterProcessorLink(
            "", CommunicationKind.MAILBOX, Set.of("a", "b"), Optional.empty(),
            Confidence.UNKNOWN, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new InterProcessorLink(
            "link", CommunicationKind.MAILBOX, Set.of("a"), Optional.empty(),
            Confidence.UNKNOWN, List.of()));
    }

    @Test
    void rejectsBlankBootRelationshipFields() {
        assertThrows(IllegalArgumentException.class, () -> bootRelationship("", "a", "b", "mechanism"));
        assertThrows(IllegalArgumentException.class, () -> bootRelationship("boot", "", "b", "mechanism"));
        assertThrows(IllegalArgumentException.class, () -> bootRelationship("boot", "a", "", "mechanism"));
        assertThrows(IllegalArgumentException.class, () -> bootRelationship("boot", "a", "b", ""));
    }

    @Test
    void rejectsDuplicateAndDanglingTopologyReferences() {
        ProcessorNode cpu = executableNode("cpu", ProcessorKind.CPU_CORE, "ARMv6-M",
            SecurityDomain.unknown(), FirmwareSource.SHARED_IMAGE);
        SharedMemoryRegion danglingMemory = new SharedMemoryRegion("sram",
            new AddressRange("cpu", 0x2000_0000L, 0x100), Set.of("missing"), Set.of(), Set.of(),
            List.of(), Confidence.UNKNOWN, List.of(DOCUMENTED));

        assertThrows(IllegalArgumentException.class, () -> new ExecutionTopology(
            List.of(cpu, cpu), List.of(), List.of(), List.of(), List.of(),
            ProgramStrategy.SHARED_PROGRAM));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionTopology(
            List.of(cpu), List.of(danglingMemory), List.of(), List.of(), List.of(),
            ProgramStrategy.SHARED_PROGRAM));
        assertThrows(IllegalArgumentException.class, () -> new BootRelationship(
            "self", "cpu", "cpu", BootRelationshipType.BOOTS, "self",
            Confidence.UNKNOWN, List.of(DOCUMENTED)));
    }

    @Test
    void rejectsEmptyTopologyAndDanglingRelationshipReferences() {
        ProcessorNode cpu = executableNode("cpu", ProcessorKind.CPU_CORE, "ARMv6-M",
            SecurityDomain.unknown(), FirmwareSource.SHARED_IMAGE);
        BootRelationship boot = bootRelationship("boot", "cpu", "missing", "reset controller");
        InterProcessorLink link = new InterProcessorLink("mailbox", CommunicationKind.MAILBOX,
            Set.of("cpu", "missing"), Optional.empty(), Confidence.UNKNOWN, List.of(DOCUMENTED));
        ProcessorGroup group = new ProcessorGroup("cores", ProcessorGroupKind.SYMMETRIC,
            Set.of("cpu", "missing"));

        assertThrows(IllegalArgumentException.class, () -> new ExecutionTopology(
            List.of(), List.of(), List.of(), List.of(), List.of(), ProgramStrategy.SHARED_PROGRAM));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionTopology(
            List.of(cpu), List.of(), List.of(boot), List.of(), List.of(),
            ProgramStrategy.SHARED_PROGRAM));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionTopology(
            List.of(cpu), List.of(), List.of(), List.of(link), List.of(),
            ProgramStrategy.SHARED_PROGRAM));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionTopology(
            List.of(cpu), List.of(), List.of(), List.of(), List.of(group),
            ProgramStrategy.SHARED_PROGRAM));
    }

    @Test
    void topologyDefensivelyCopiesCollections() {
        ArrayList<ProcessorNode> processors = new ArrayList<>();
        processors.add(executableNode("cpu", ProcessorKind.CPU_CORE, "ARMv6-M",
            SecurityDomain.unknown(), FirmwareSource.SHARED_IMAGE));
        ExecutionTopology topology = new ExecutionTopology(processors, List.of(), List.of(),
            List.of(), List.of(), ProgramStrategy.SHARED_PROGRAM);

        processors.clear();

        assertEquals(1, topology.processors().size());
        assertThrows(UnsupportedOperationException.class, () -> topology.processors().clear());
    }

    private static ProcessorNode executableNode(
            String id,
            ProcessorKind kind,
            String isa,
            SecurityDomain securityDomain,
            FirmwareSource firmwareSource) {
        ResetEntry reset = new ResetEntry("reset", "cpu", 0x1000, Confidence.DERIVED,
            List.of(DOCUMENTED));
        return new ProcessorNode(id, kind, Optional.of(isa), Optional.of("language:" + isa),
            Optional.of("default"), "application", securityDomain, "soc", Set.of("cpu"),
            List.of(reset), firmwareSource, Confidence.DERIVED, List.of(DOCUMENTED));
    }

    private static ProcessorNode processorWithFields(
            String id,
            Optional<String> isa,
            Optional<String> language,
            Optional<String> compiler,
            String role,
            String owner,
            Set<String> addressSpaces) {
        return new ProcessorNode(id, ProcessorKind.CPU_CORE, isa, language, compiler, role,
            SecurityDomain.unknown(), owner, addressSpaces, List.of(), FirmwareSource.SHARED_IMAGE,
            Confidence.UNKNOWN, List.of(DOCUMENTED));
    }

    private static BootRelationship bootRelationship(
            String id, String source, String target, String mechanism) {
        return new BootRelationship(id, source, target, BootRelationshipType.BOOTS, mechanism,
            Confidence.UNKNOWN, List.of(DOCUMENTED));
    }
}
