package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable inputs for one STM32 firmware comparison.
 *
 * <p>At least one confirmed artifact is required; a baseline slot must carry a
 * baseline-role artifact and a candidate slot a candidate-role artifact.
 * Binding both artifacts to one exact part and to the digest-pinned curated
 * selection is enforced by {@link Stm32FirmwareDiffAnalyzer} with typed
 * diagnostics, so this record stays a structural input holder.</p>
 */
public record Stm32FirmwareDiffContext(
        Stm32PartSelection selection,
        Optional<Stm32FirmwareArtifact> baseline,
        Optional<Stm32FirmwareArtifact> candidate) {
    public Stm32FirmwareDiffContext {
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(baseline, "baseline");
        Objects.requireNonNull(candidate, "candidate");
        if (baseline.isEmpty() && candidate.isEmpty()) {
            throw new IllegalArgumentException("At least one firmware artifact is required");
        }
        if (baseline.isPresent()
                && baseline.orElseThrow().role() != Stm32FirmwareRole.BASELINE) {
            throw new IllegalArgumentException("Baseline input has the wrong role");
        }
        if (candidate.isPresent()
                && candidate.orElseThrow().role() != Stm32FirmwareRole.CANDIDATE) {
            throw new IllegalArgumentException("Candidate input has the wrong role");
        }
    }
}
