package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable model of the fuse bit map for an Atmel/Microchip microcontroller.
 */
public record AtmelFuseMap(
        String state,
        String reason,
        List<AtmelFuseByte> bytes) {

    public AtmelFuseMap {
        Objects.requireNonNull(state, "state must not be null");
        reason = reason == null ? "" : reason;
        bytes = bytes == null ? List.of() : List.copyOf(bytes);
    }

    public boolean isPinned() {
        return "PINNED".equalsIgnoreCase(state);
    }

    public boolean isAvailable() {
        return isPinned() && !bytes.isEmpty();
    }

    public Optional<AtmelFuseByte> findByteByName(String byteName) {
        if (byteName == null || byteName.isBlank()) {
            return Optional.empty();
        }
        for (AtmelFuseByte b : bytes) {
            if (b.name().equalsIgnoreCase(byteName.trim())) {
                return Optional.of(b);
            }
        }
        return Optional.empty();
    }

    public Optional<AtmelFuseByte> findByteByAddress(long targetAddress) {
        for (AtmelFuseByte b : bytes) {
            if (b.address() == targetAddress) {
                return Optional.of(b);
            }
        }
        return Optional.empty();
    }
}
