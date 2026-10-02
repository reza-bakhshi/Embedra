package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.targets.stm32.vector.Stm32VectorPlanner;
import java.util.List;
import java.util.Objects;

/**
 * Redacted comparison metadata for one validated STM32 firmware image.
 *
 * <p>The record carries the confirmed facts a diff may consume: the bound exact
 * part, the caller's artifact identity, the role inside the comparison, the
 * confirmed mapped image extent (reusing the T041 {@code ImageRange} contract),
 * the validated content SHA-256, and the provenance of the confirming import.
 * No firmware bytes, symbol, or device fact is carried or derived.</p>
 */
public record Stm32FirmwareArtifact(
        String exactPart,
        String id,
        Stm32FirmwareRole role,
        Stm32VectorPlanner.ImageRange imageRange,
        String sha256,
        List<Evidence> evidence) {

    public Stm32FirmwareArtifact {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(imageRange, "imageRange");
        Objects.requireNonNull(sha256, "sha256");
        evidence = List.copyOf(evidence);
        if (exactPart.isBlank() || id.isBlank() || !sha256.matches("[0-9a-f]{64}")
                || evidence.isEmpty()) {
            throw new IllegalArgumentException(
                "STM32 firmware artifact identity or provenance is incomplete");
        }
    }
}
