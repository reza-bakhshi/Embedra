package io.github.rezabakhshi.embedra.targets.esp;

import java.util.Objects;

/** One exact chip-ID definition with its upstream provenance. */
public record EspressifChipDefinition(
        int chipId,
        String deviceId,
        String displayName,
        String sourcePath,
        String sourceRevision,
        String sourceLicense) {
    public EspressifChipDefinition {
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(sourcePath, "sourcePath");
        Objects.requireNonNull(sourceRevision, "sourceRevision");
        Objects.requireNonNull(sourceLicense, "sourceLicense");
        if (chipId < 0 || chipId > 0xffff || deviceId.isBlank() || displayName.isBlank()
            || sourcePath.isBlank() || sourceRevision.isBlank() || sourceLicense.isBlank()) {
            throw new IllegalArgumentException("Chip definition must be complete");
        }
    }
}
