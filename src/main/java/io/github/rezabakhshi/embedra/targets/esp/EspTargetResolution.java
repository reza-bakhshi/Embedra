package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.Objects;

/** A provider selection backed by its exact support decision and topology. */
public record EspTargetResolution(
        EspTargetProvider provider,
        SupportDecision support,
        ExecutionTopology topology) {
    public EspTargetResolution {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(support, "support");
        Objects.requireNonNull(topology, "topology");
        if (!support.supported()) {
            throw new IllegalArgumentException("A target resolution requires supported evidence");
        }
    }
}
