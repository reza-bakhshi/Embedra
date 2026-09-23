package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.formats.esp.EspExecutableRole;
import io.github.rezabakhshi.embedra.formats.esp.EspPartitionEntry;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Immutable inputs for one factory-to-OTA comparison and ESP lead scan. */
public record EspFactoryOtaContext(
        Optional<EspFirmwareArtifact> factory,
        Optional<EspFirmwareArtifact> ota,
        List<EspPartitionEntry> partitions) {
    public EspFactoryOtaContext {
        Objects.requireNonNull(factory, "factory");
        Objects.requireNonNull(ota, "ota");
        partitions = List.copyOf(partitions);
        if (factory.isEmpty() && ota.isEmpty()) {
            throw new IllegalArgumentException("At least one firmware artifact is required");
        }
        if (factory.isPresent() && factory.orElseThrow().role() != EspExecutableRole.FACTORY) {
            throw new IllegalArgumentException("Factory input has the wrong role");
        }
        if (ota.isPresent() && ota.orElseThrow().role() != EspExecutableRole.OTA) {
            throw new IllegalArgumentException("OTA input has the wrong role");
        }
    }
}
