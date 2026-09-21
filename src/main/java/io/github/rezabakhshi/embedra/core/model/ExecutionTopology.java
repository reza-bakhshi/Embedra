package io.github.rezabakhshi.embedra.core.model;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Validated immutable graph of processors, memory, boot, and communication relationships. */
public record ExecutionTopology(
        List<ProcessorNode> processors,
        List<SharedMemoryRegion> sharedMemories,
        List<BootRelationship> bootRelationships,
        List<InterProcessorLink> communicationLinks,
        List<ProcessorGroup> processorGroups,
        ProgramStrategy programStrategy) {
    public ExecutionTopology {
        processors = List.copyOf(processors);
        sharedMemories = List.copyOf(sharedMemories);
        bootRelationships = List.copyOf(bootRelationships);
        communicationLinks = List.copyOf(communicationLinks);
        processorGroups = List.copyOf(processorGroups);
        Objects.requireNonNull(programStrategy, "programStrategy");
        if (processors.isEmpty()) {
            throw new IllegalArgumentException("An execution topology requires at least one processor node");
        }

        Set<String> processorIds = uniqueProcessorIds(processors);
        ensureUniqueIds(sharedMemories.stream().map(SharedMemoryRegion::id).toList(), "shared memory");
        ensureUniqueIds(bootRelationships.stream().map(BootRelationship::id).toList(), "boot relationship");
        ensureUniqueIds(communicationLinks.stream().map(InterProcessorLink::id).toList(),
            "communication link");
        ensureUniqueIds(processorGroups.stream().map(ProcessorGroup::id).toList(), "processor group");

        for (SharedMemoryRegion memory : sharedMemories) {
            ensureKnownProcessors(memory.referencedProcessorIds(), processorIds, "shared memory " + memory.id());
        }
        for (BootRelationship relationship : bootRelationships) {
            ensureKnownProcessors(Set.of(relationship.sourceNodeId(), relationship.targetNodeId()),
                processorIds, "boot relationship " + relationship.id());
        }
        for (InterProcessorLink link : communicationLinks) {
            ensureKnownProcessors(link.participantNodeIds(), processorIds, "communication link " + link.id());
        }
        for (ProcessorGroup group : processorGroups) {
            ensureKnownProcessors(group.memberNodeIds(), processorIds, "processor group " + group.id());
        }
    }

    public Set<String> processorIds() {
        return Set.copyOf(processors.stream().map(ProcessorNode::id).toList());
    }

    private static Set<String> uniqueProcessorIds(List<ProcessorNode> processors) {
        List<String> ids = processors.stream().map(ProcessorNode::id).toList();
        ensureUniqueIds(ids, "processor");
        return Set.copyOf(ids);
    }

    private static void ensureUniqueIds(List<String> ids, String type) {
        if (new HashSet<>(ids).size() != ids.size()) {
            throw new IllegalArgumentException("Duplicate " + type + " ID");
        }
    }

    private static void ensureKnownProcessors(Set<String> references, Set<String> processorIds, String owner) {
        if (!processorIds.containsAll(references)) {
            HashSet<String> unknown = new HashSet<>(references);
            unknown.removeAll(processorIds);
            throw new IllegalArgumentException(owner + " references unknown processor nodes: " + unknown);
        }
    }
}
