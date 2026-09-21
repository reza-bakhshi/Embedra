package io.github.rezabakhshi.embedra.core.report;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Canonical report projection of an execution topology. */
public final class ExecutionTopologyReport {
    public static final String SCHEMA_ID = "urn:embedra:schema:execution-topology:1";

    private final ExecutionTopology topology;

    private ExecutionTopologyReport(ExecutionTopology topology) {
        this.topology = topology;
    }

    public static ExecutionTopologyReport from(ExecutionTopology topology) {
        return new ExecutionTopologyReport(Objects.requireNonNull(topology, "topology"));
    }

    public String toCanonicalJson() {
        return CanonicalJson.write(canonicalValue());
    }

    Map<String, Object> canonicalValue() {
        return Map.of(
            "schemaId", SCHEMA_ID,
            "programStrategy", topology.programStrategy().name(),
            "processors", topology.processors().stream()
                .sorted(Comparator.comparing(node -> node.id())).map(node -> {
                    HashMap<String, Object> value = new HashMap<>();
                    value.put("id", node.id());
                    value.put("kind", node.kind().name());
                    value.put("instructionSet", node.instructionSet().orElse(null));
                    value.put("ghidraLanguageId", node.ghidraLanguageId().orElse(null));
                    value.put("compilerSpecId", node.compilerSpecId().orElse(null));
                    value.put("role", node.role());
                    value.put("securityDomain", Map.of("id", node.securityDomain().id(),
                        "kind", node.securityDomain().kind().name()));
                    value.put("ownership", node.ownership());
                    value.put("addressSpaces", node.addressSpaces().stream().sorted().toList());
                    value.put("resetEntries", node.resetEntries().stream()
                        .sorted(Comparator.comparing(entry -> entry.name())).map(entry -> Map.of(
                            "name", entry.name(), "addressSpace", entry.addressSpace(),
                            "address", entry.address(), "confidence", entry.confidence().name(),
                            "evidence", evidenceValues(entry.evidence()))).toList());
                    value.put("firmwareSource", node.firmwareSource().name());
                    value.put("confidence", node.confidence().name());
                    value.put("evidence", evidenceValues(node.evidence()));
                    return value;
                }).toList(),
            "sharedMemories", topology.sharedMemories().stream()
                .sorted(Comparator.comparing(memory -> memory.id())).map(memory -> Map.of(
                    "id", memory.id(), "range", rangeValue(memory.range()),
                    "owners", memory.ownerNodeIds().stream().sorted().toList(),
                    "readers", memory.readerNodeIds().stream().sorted().toList(),
                    "writers", memory.writerNodeIds().stream().sorted().toList(),
                    "aliases", memory.aliases().stream().map(ExecutionTopologyReport::rangeValue).toList(),
                    "confidence", memory.confidence().name(),
                    "evidence", evidenceValues(memory.evidence()))).toList(),
            "bootRelationships", topology.bootRelationships().stream()
                .sorted(Comparator.comparing(relationship -> relationship.id())).map(relationship -> Map.of(
                    "id", relationship.id(), "sourceNodeId", relationship.sourceNodeId(),
                    "targetNodeId", relationship.targetNodeId(), "type", relationship.type().name(),
                    "mechanism", relationship.mechanism(), "confidence", relationship.confidence().name(),
                    "evidence", evidenceValues(relationship.evidence()))).toList(),
            "communicationLinks", topology.communicationLinks().stream()
                .sorted(Comparator.comparing(link -> link.id())).map(link -> {
                    HashMap<String, Object> value = new HashMap<>();
                    value.put("id", link.id());
                    value.put("kind", link.kind().name());
                    value.put("participants", link.participantNodeIds().stream().sorted().toList());
                    value.put("registerRange", link.registerRange()
                        .map(ExecutionTopologyReport::rangeValue).orElse(null));
                    value.put("confidence", link.confidence().name());
                    value.put("evidence", evidenceValues(link.evidence()));
                    return value;
                }).toList(),
            "processorGroups", topology.processorGroups().stream()
                .sorted(Comparator.comparing(group -> group.id())).map(group -> Map.of(
                    "id", group.id(), "kind", group.kind().name(),
                    "members", group.memberNodeIds().stream().sorted().toList())).toList());
    }

    private static Map<String, Object> rangeValue(AddressRange range) {
        return Map.of("addressSpace", range.addressSpace(), "start", range.start(), "length", range.length());
    }

    private static List<Map<String, Object>> evidenceValues(List<Evidence> evidence) {
        return evidence.stream().sorted(Comparator.comparing((Evidence item) -> item.kind().name())
            .thenComparing(Evidence::source).thenComparing(Evidence::detail)).map(item -> Map.<String, Object>of(
                "kind", item.kind().name(), "source", item.source(), "detail", item.detail())).toList();
    }
}
