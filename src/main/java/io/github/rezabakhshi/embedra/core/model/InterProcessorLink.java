package io.github.rezabakhshi.embedra.core.model;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Mailbox, FIFO, semaphore, or interrupt relationship between processors. */
public record InterProcessorLink(
        String id,
        CommunicationKind kind,
        Set<String> participantNodeIds,
        Optional<AddressRange> registerRange,
        Confidence confidence,
        List<Evidence> evidence) {
    public InterProcessorLink {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(registerRange, "registerRange");
        Objects.requireNonNull(confidence, "confidence");
        participantNodeIds = Set.copyOf(participantNodeIds);
        evidence = List.copyOf(evidence);
        if (id.isBlank()) {
            throw new IllegalArgumentException("Communication-link ID must not be blank");
        }
        if (participantNodeIds.size() < 2) {
            throw new IllegalArgumentException("Communication links require at least two participants");
        }
    }
}
