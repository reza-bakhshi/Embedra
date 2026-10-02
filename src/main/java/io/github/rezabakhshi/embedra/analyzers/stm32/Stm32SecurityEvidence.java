package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/**
 * Explicit availability of the pinned T044 TrustZone evidence for one part.
 *
 * <p>{@code PINNED} restates a digest-pinned security record and its secure
 * alias apertures with their provenance; {@code UNAVAILABLE} carries the
 * record's own pinned reason; {@code NOT_SUPPLIED} records that no confirmed
 * security record was given to the enrichment. Unavailable security evidence is
 * never turned into a lead.</p>
 */
public record Stm32SecurityEvidence(
        String exactPart,
        Status status,
        String reason,
        List<String> pinnedWindowIds,
        List<Evidence> evidence) {

    /** Security-evidence availability for the analyzed part. */
    public enum Status {
        PINNED,
        UNAVAILABLE,
        NOT_SUPPLIED
    }

    public Stm32SecurityEvidence {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(pinnedWindowIds, "pinnedWindowIds");
        Objects.requireNonNull(evidence, "evidence");
        pinnedWindowIds = List.copyOf(pinnedWindowIds);
        evidence = List.copyOf(evidence);
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Security evidence requires an exact part");
        }
        if (status == Status.PINNED) {
            if (reason != null) {
                throw new IllegalArgumentException(
                    "Pinned security evidence must not carry a reason");
            }
            if (pinnedWindowIds.isEmpty() || evidence.isEmpty()) {
                throw new IllegalArgumentException(
                    "Pinned security evidence requires windows and evidence");
            }
        }
        else {
            if (reason == null || reason.isBlank() || !pinnedWindowIds.isEmpty()) {
                throw new IllegalArgumentException(
                    "Unavailable security evidence requires a reason and no windows");
            }
        }
    }
}
