package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.List;
import java.util.Objects;

/** Immutable deterministic T025 comparison and ESP-specific lead report. */
public record EspFactoryOtaReport(
        EspArtifactDiff diff, List<EspCtfFinding> findings, List<String> detectorsRun) {
    public EspFactoryOtaReport {
        Objects.requireNonNull(diff, "diff");
        findings = List.copyOf(findings);
        detectorsRun = List.copyOf(detectorsRun);
    }
}
