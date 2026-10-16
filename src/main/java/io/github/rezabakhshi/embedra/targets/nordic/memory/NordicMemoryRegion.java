package io.github.rezabakhshi.embedra.targets.nordic.memory;

import java.util.Objects;

/**
 * Immutable representation of a contiguous memory region in a Nordic microcontroller address space.
 */
public record NordicMemoryRegion(
        String name,
        NordicMemoryRegionKind kind,
        long startAddress,
        long sizeBytes,
        boolean readable,
        boolean writable,
        boolean executable,
        boolean secure) {

    public NordicMemoryRegion {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(kind, "kind must not be null");
        if (sizeBytes <= 0) {
            throw new IllegalArgumentException("sizeBytes must be positive: " + sizeBytes);
        }
        if (startAddress < 0) {
            throw new IllegalArgumentException("startAddress cannot be negative: " + startAddress);
        }
    }

    public long endAddress() {
        return startAddress + sizeBytes - 1L;
    }

    public boolean contains(long address) {
        return address >= startAddress && address <= endAddress();
    }

    public boolean overlaps(NordicMemoryRegion other) {
        Objects.requireNonNull(other, "other must not be null");
        return this.startAddress <= other.endAddress() && other.startAddress <= this.endAddress();
    }
}
