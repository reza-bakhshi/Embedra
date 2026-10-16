package io.github.rezabakhshi.embedra.targets.atmel.memory;

import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable planned memory layout for an Atmel / Microchip microcontroller.
 */
public final class AtmelMemoryPlan {

    private final AtmelPartRecord part;

    private final List<AtmelMemoryRegion> regions;

    public AtmelMemoryPlan(AtmelPartRecord part, List<AtmelMemoryRegion> regions) {
        this.part = Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(regions, "regions must not be null");
        this.regions = Collections.unmodifiableList(List.copyOf(regions));
    }

    public AtmelPartRecord part() {
        return part;
    }

    public List<AtmelMemoryRegion> regions() {
        return regions;
    }

    public List<AtmelMemoryRegion> regionsForSpace(String space) {
        Objects.requireNonNull(space, "space must not be null");
        return regions.stream()
            .filter(r -> r.addressSpace().equalsIgnoreCase(space))
            .toList();
    }

    public Optional<AtmelMemoryRegion> findRegion(String space, long address) {
        Objects.requireNonNull(space, "space must not be null");
        for (AtmelMemoryRegion region : regions) {
            if (region.addressSpace().equalsIgnoreCase(space) && region.contains(address)) {
                return Optional.of(region);
            }
        }
        return Optional.empty();
    }

    public boolean isMapped(String space, long address) {
        return findRegion(space, address).isPresent();
    }

    public boolean isExecutable(String space, long address) {
        return findRegion(space, address)
            .map(AtmelMemoryRegion::execute)
            .orElse(false);
    }
}
