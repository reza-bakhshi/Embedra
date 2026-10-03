package io.github.rezabakhshi.embedra.targets.rp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import java.util.Objects;

/**
 * An individual memory region with permissions and description.
 */
public record RpMemoryRegion(
        String id,
        RpMemoryRegionKind kind,
        AddressRange range,
        boolean readable,
        boolean writable,
        boolean executable,
        String description) {

    public RpMemoryRegion {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(kind, "kind must not be null");
        Objects.requireNonNull(range, "range must not be null");
        Objects.requireNonNull(description, "description must not be null");
    }

    public boolean contains(long address) {
        return address >= range.start() && address < range.endExclusive();
    }
}
