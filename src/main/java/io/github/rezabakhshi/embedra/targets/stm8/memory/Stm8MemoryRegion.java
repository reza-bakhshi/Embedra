package io.github.rezabakhshi.embedra.targets.stm8.memory;

import java.util.Objects;

/**
 * Immutable memory region in the STM8 24-bit linear address space.
 */
public record Stm8MemoryRegion(
        String name,
        Stm8MemoryRegionKind kind,
        long startAddress,
        long sizeBytes,
        boolean readable,
        boolean writable,
        boolean executable,
        boolean volatileAccess) {

    public Stm8MemoryRegion {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(kind, "kind must not be null");
        if (name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        if (startAddress < 0 || startAddress > 0xFFFFFFL) {
            throw new IllegalArgumentException("startAddress out of 24-bit range: " + startAddress);
        }
        if (sizeBytes <= 0) {
            throw new IllegalArgumentException("sizeBytes must be positive: " + sizeBytes);
        }
        if (startAddress + sizeBytes - 1L > 0xFFFFFFL) {
            throw new IllegalArgumentException("Region extends beyond 24-bit address space");
        }
    }

    public long endAddress() {
        return startAddress + sizeBytes - 1L;
    }

    public boolean contains(long address) {
        return address >= startAddress && address <= endAddress();
    }

    public boolean overlaps(Stm8MemoryRegion other) {
        Objects.requireNonNull(other, "other must not be null");
        return startAddress <= other.endAddress() && other.startAddress <= endAddress();
    }
}
