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

    private static ProcessorNode node(String id, String isa, SecurityDomain securityDomain) {
        return new ProcessorNode(id, ProcessorKind.CPU_CORE, Optional.of(isa),
            Optional.of("language:" + isa), Optional.of("default"), "application",
            securityDomain, "soc", Set.of("cpu"), List.of(), FirmwareSource.INDEPENDENT_IMAGE,
            Confidence.VERIFIED, List.of(EVIDENCE));
    }
}
