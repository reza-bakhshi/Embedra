package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.formats.esp.EspExecutableRole;
import io.github.rezabakhshi.embedra.formats.esp.EspFlashRange;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/** Redacted comparison metadata for one validated factory or OTA image. */
public record EspFirmwareArtifact(
        String id,
        EspExecutableRole role,
        Optional<String> partitionLabel,
        EspFlashRange flashRange,
        String sha256,
        Optional<String> version,
        OptionalLong secureVersion,
        EspImageHashState imageHashState) {
    public EspFirmwareArtifact {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(partitionLabel, "partitionLabel");
        Objects.requireNonNull(flashRange, "flashRange");
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(secureVersion, "secureVersion");
        Objects.requireNonNull(imageHashState, "imageHashState");
        if (id.isBlank() || !sha256.matches("[0-9a-f]{64}")
            || flashRange.length() == 0 || secureVersion.orElse(0) < 0
            || (role != EspExecutableRole.FACTORY && role != EspExecutableRole.OTA)) {
            throw new IllegalArgumentException("Invalid factory/OTA firmware artifact");
        }
        partitionLabel.ifPresent(label -> {
            if (label.isBlank()) {
                throw new IllegalArgumentException("Partition label must not be blank");
            }
        });
        version.ifPresent(value -> {
            if (value.isBlank()) {
                throw new IllegalArgumentException("Version must not be blank");
            }
        });
    }
}
