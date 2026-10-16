package io.github.rezabakhshi.embedra.targets.atmel.vector;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable parsed interrupt vector table for an Atmel / Microchip microcontroller.
 */
public final class AtmelVectorTable {

    private final long tableBaseAddress;

    private final AtmelPartRecord part;

    private final List<AtmelVectorEntry> entries;

    private final AtmelVectorTableScore score;

    public AtmelVectorTable(
            long tableBaseAddress,
            AtmelPartRecord part,
            List<AtmelVectorEntry> entries,
            AtmelVectorTableScore score) {
        this.tableBaseAddress = tableBaseAddress;
        this.part = Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(entries, "entries must not be null");
        this.entries = Collections.unmodifiableList(List.copyOf(entries));
        this.score = Objects.requireNonNull(score, "score must not be null");
    }

    public long tableBaseAddress() {
        return tableBaseAddress;
    }

    public AtmelPartRecord part() {
        return part;
    }

    public List<AtmelVectorEntry> entries() {
        return entries;
    }

    public AtmelVectorTableScore score() {
        return score;
    }

    public int entryCount() {
        return entries.size();
    }

    public Optional<AtmelVectorEntry> resetEntry() {
        for (AtmelVectorEntry entry : entries) {
            if (entry.isReset() && entry.isValid()) {
                return Optional.of(entry);
            }
        }
        return Optional.empty();
    }

    public boolean isConfident() {
        return score.confidence() == Confidence.VERIFIED || score.confidence() == Confidence.DERIVED;
    }
}
