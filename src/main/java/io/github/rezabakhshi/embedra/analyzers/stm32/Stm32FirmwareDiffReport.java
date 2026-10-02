package io.github.rezabakhshi.embedra.analyzers.stm32;

import java.util.List;
import java.util.Objects;

/** Immutable deterministic T048 comparison report for two STM32 artifacts. */
public record Stm32FirmwareDiffReport(Stm32ArtifactDiff diff, List<String> detectorsRun) {
    public Stm32FirmwareDiffReport {
        Objects.requireNonNull(diff, "diff");
        detectorsRun = List.copyOf(detectorsRun);
    }
}
