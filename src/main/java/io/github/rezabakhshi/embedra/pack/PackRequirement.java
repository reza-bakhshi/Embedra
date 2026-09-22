package io.github.rezabakhshi.embedra.pack;

import java.util.Objects;
import java.util.Optional;

/** Offline selection constraints for one installed pack identity. */
public record PackRequirement(
        String packId, Optional<PackVersion> exactVersion, Optional<String> deviceId) {
    public PackRequirement {
        PackManifest.requirePackId(packId);
        Objects.requireNonNull(exactVersion, "exactVersion");
        Objects.requireNonNull(deviceId, "deviceId");
        deviceId.ifPresent(value -> PackManifest.requireIdentifier(value, "device ID"));
    }
}
