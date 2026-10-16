package io.github.rezabakhshi.embedra.targets.atmel.memory;

import java.util.Objects;

/**
 * Immutable memory region in an Atmel / Microchip target address space.
 */
public record AtmelMemoryRegion(
        String name,
        AtmelMemoryRegionKind kind,
        String addressSpace,
        long start,
        long length,
        boolean read,
        boolean write,
        boolean execute,
        boolean isVolatile) {

    public AtmelMemoryRegion {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(kind, "kind must not be null");
        Objects.requireNonNull(addressSpace, "addressSpace must not be null");
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive: " + length);
        }
    }

    public long end() {
        return start + length - 1L;
    }

    public boolean contains(long address) {
        return address >= start && address <= end();
    }
}
