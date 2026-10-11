package io.github.rezabakhshi.embedra.core.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.ProcessorGroup;
import io.github.rezabakhshi.embedra.core.model.ProcessorGroupKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.test.SnapshotAssertions;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ExecutionTopologyReportTest {
    private static final Evidence EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD, "synthetic fixture", "processor topology");

    @Test
    void topologyReportSortsNodesAndRetainsArchitectureAndSecurityDistinctions() {
        ProcessorNode riscv = node("riscv", "Hazard3", SecurityDomain.unknown());
        ProcessorNode arm = node("arm-secure", "ARMv8-M", SecurityDomain.secure());
        ExecutionTopology topology = new ExecutionTopology(List.of(riscv, arm), List.of(), List.of(),
            List.of(), List.of(new ProcessorGroup("architectures", ProcessorGroupKind.ALTERNATIVE_BOOT,
                Set.of("riscv", "arm-secure"))), ProgramStrategy.SEPARATE_PROGRAMS);

        String json = ExecutionTopologyReport.from(topology).toCanonicalJson();

        SnapshotAssertions.assertMatches("snapshots/execution-topology.json", json);
        assertTrue(json.contains("\"programStrategy\":\"SEPARATE_PROGRAMS\""));
        assertFalse(json.contains("timestamp"));
    }

    @Test
    void topologyReportFullComponents() {
        ProcessorNode arm = new ProcessorNode("arm", ProcessorKind.CPU_CORE, Optional.of("ARMv7-M"),
            Optional.of("language:ARMv7-M"), Optional.of("default"), "application",
            SecurityDomain.nonSecure(), "soc", Set.of("cpu"),
            List.of(new io.github.rezabakhshi.embedra.core.model.ResetEntry("reset", "mem",
                0x08000000L, Confidence.VERIFIED, List.of(EVIDENCE))),
            FirmwareSource.INDEPENDENT_IMAGE, Confidence.VERIFIED, List.of(EVIDENCE));
        ProcessorNode coproc = new ProcessorNode("coproc", ProcessorKind.PROGRAMMABLE_COPROCESSOR, Optional.of("M0"),
            Optional.of("language:M0"), Optional.of("default"), "coprocessor",
            SecurityDomain.nonSecure(), "soc", Set.of("cpu"), List.of(),
            FirmwareSource.INDEPENDENT_IMAGE, Confidence.VERIFIED, List.of(EVIDENCE));

        io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion shmem =
            new io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion("sram",
                new io.github.rezabakhshi.embedra.core.io.AddressRange("mem", 0x20000000L, 0x1000L),
                Set.of("arm"), Set.of("coproc"), Set.of("arm"),
                List.of(new io.github.rezabakhshi.embedra.core.io.AddressRange("mem", 0x10000000L, 0x1000L)),
                Confidence.VERIFIED, List.of(EVIDENCE));

        io.github.rezabakhshi.embedra.core.model.BootRelationship boot =
            new io.github.rezabakhshi.embedra.core.model.BootRelationship("boot1", "arm", "coproc",
                io.github.rezabakhshi.embedra.core.model.BootRelationshipType.RELEASES_FROM_RESET,
                "register", Confidence.VERIFIED, List.of(EVIDENCE));

        io.github.rezabakhshi.embedra.core.model.InterProcessorLink link =
            new io.github.rezabakhshi.embedra.core.model.InterProcessorLink("mailbox1",
                io.github.rezabakhshi.embedra.core.model.CommunicationKind.MAILBOX,
                Set.of("arm", "coproc"),
                Optional.of(new io.github.rezabakhshi.embedra.core.io.AddressRange("mem", 0x40000000L, 0x100L)),
                Confidence.VERIFIED, List.of(EVIDENCE));

        ExecutionTopology topology = new ExecutionTopology(List.of(arm, coproc),
            List.of(shmem), List.of(boot), List.of(link), List.of(),
            ProgramStrategy.SHARED_PROGRAM);

        String json = ExecutionTopologyReport.from(topology).toCanonicalJson();
        assertTrue(json.contains("\"sharedMemories\":["));
        assertTrue(json.contains("\"bootRelationships\":["));
        assertTrue(json.contains("\"communicationLinks\":["));
        assertTrue(json.contains("\"resetEntries\":["));
    }

    private static ProcessorNode node(String id, String isa, SecurityDomain securityDomain) {
        return new ProcessorNode(id, ProcessorKind.CPU_CORE, Optional.of(isa),
            Optional.of("language:" + isa), Optional.of("default"), "application",
            securityDomain, "soc", Set.of("cpu"), List.of(), FirmwareSource.INDEPENDENT_IMAGE,
            Confidence.VERIFIED, List.of(EVIDENCE));
    }
}
