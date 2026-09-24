package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import java.util.List;
import java.util.Objects;

/** ISA-neutral classification of encoded ESP load ranges from provider-owned data. */
public final class EspMemoryMap {
    private final String addressSpace;

    private final List<EspMemoryRegion> regions;

    public EspMemoryMap(String addressSpace, List<EspMemoryRegion> regions) {
        Objects.requireNonNull(addressSpace, "addressSpace");
        Objects.requireNonNull(regions, "regions");
        if (addressSpace.isBlank() || regions.isEmpty()) {
            throw new IllegalArgumentException("ESP memory map must name a space and regions");
        }
        this.addressSpace = addressSpace;
        this.regions = List.copyOf(regions);
        this.regions.forEach(region -> Objects.requireNonNull(region, "region"));
    }

    public MemoryClassification classify(AddressRange range) {
        Objects.requireNonNull(range, "range");
        for (EspMemoryRegion region : regions) {
            if (range.addressSpace().equals(addressSpace) && range.length() > 0
                && range.start() >= region.start()
                && range.endExclusive() <= region.endExclusive()) {
                return new MemoryClassification(range, region.kind(), true,
                    region.readable(), region.writable(), region.executable(),
                    List.of(region.evidence()));
            }
        }
        return new MemoryClassification(range, MemoryRegionKind.UNKNOWN, false,
            false, false, false, regions.stream().map(EspMemoryRegion::evidence)
                .distinct().toList());
    }
}
