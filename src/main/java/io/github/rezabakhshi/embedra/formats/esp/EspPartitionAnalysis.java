package io.github.rezabakhshi.embedra.formats.esp;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Immutable aggregate of explicit partition-handler results. */
public record EspPartitionAnalysis(
        List<EspPartitionInspection> inspections,
        Optional<EspOtaSelection> otaSelection) {
    public EspPartitionAnalysis {
        inspections = List.copyOf(inspections);
        Objects.requireNonNull(otaSelection, "otaSelection");
    }
}
