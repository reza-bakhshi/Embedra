package io.github.rezabakhshi.embedra.targets.stm8.vector;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Decoded and scored STM8 interrupt vector table anchored at 0x008000.
 */
public record Stm8VectorTable(
        long baseAddress,
        List<Stm8VectorEntry> entries,
        Stm8VectorTableScore score,
        long resetTargetAddress) {

    public Stm8VectorTable {
        Objects.requireNonNull(score, "score must not be null");
        entries = entries == null ? List.of() : List.copyOf(entries);
        if (entries.size() != 32) {
            throw new IllegalArgumentException("STM8 vector table must contain exactly 32 entries, got: "
                + entries.size());
        }
    }

    public Optional<Stm8VectorEntry> entry(int slotIndex) {
        if (slotIndex < 0 || slotIndex >= entries.size()) {
            return Optional.empty();
        }
        return Optional.of(entries.get(slotIndex));
    }

    public Optional<Stm8VectorEntry> entryByLabel(String label) {
        if (label == null || label.isBlank()) {
            return Optional.empty();
        }
        for (Stm8VectorEntry entry : entries) {
            if (entry.handlerLabel().equalsIgnoreCase(label.trim())) {
                return Optional.of(entry);
            }
        }
        return Optional.empty();
    }

    public List<Stm8VectorEntry> validEntries() {
        return entries.stream().filter(Stm8VectorEntry::isValid).toList();
    }

    public boolean isConfident() {
        return score.confidence() == Confidence.VERIFIED || score.confidence() == Confidence.DERIVED;
    }

}
