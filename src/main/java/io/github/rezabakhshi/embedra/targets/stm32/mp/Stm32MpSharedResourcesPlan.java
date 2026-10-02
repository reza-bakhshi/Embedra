package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.InterProcessorLink;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Shared memory, mailbox, and hardware semaphore resource allocation model.
 *
 * <p>Captures shared SRAM regions, alias apertures, inter-processor communication
 * controllers (IPCC), and hardware semaphores (HSEM) without weakening MCU memory
 * isolation assumptions.</p>
 */
public record Stm32MpSharedResourcesPlan(
        String exactPart,
        List<SharedMemoryRegion> sharedMemories,
        List<InterProcessorLink> communicationLinks,
        Confidence confidence,
        List<Evidence> evidence) {

    public Stm32MpSharedResourcesPlan {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(confidence, "confidence");
        sharedMemories = List.copyOf(sharedMemories);
        communicationLinks = List.copyOf(communicationLinks);
        evidence = List.copyOf(evidence);

        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Exact part must not be blank");
        }
        Set<String> memIds = new HashSet<>();
        for (SharedMemoryRegion m : sharedMemories) {
            if (!memIds.add(m.id())) {
                throw new IllegalArgumentException("Duplicate shared memory ID: " + m.id());
            }
        }
        Set<String> linkIds = new HashSet<>();
        for (InterProcessorLink l : communicationLinks) {
            if (!linkIds.add(l.id())) {
                throw new IllegalArgumentException("Duplicate communication link ID: " + l.id());
            }
        }
    }
}
