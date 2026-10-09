package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Immutable snapshot of a memory block or region for workspace diffing (T062).
 *
 * @param name block name (e.g. .text, .data, IROM, DRAM, FLASH)
 * @param startAddress base memory address
 * @param size size in bytes
 * @param permissions permission string (e.g. "R", "RW", "RX", "RWX")
 * @param blockHash cryptographic hash of the block contents (or empty string if unhashed)
 */
public record MemoryBlockSnapshot(
        String name,
        long startAddress,
        long size,
        String permissions,
        String blockHash) {

    public MemoryBlockSnapshot {
        Objects.requireNonNull(name, "name must not be null");
        permissions = permissions == null ? "R" : permissions;
        blockHash = blockHash == null ? "" : blockHash;
        if (startAddress < 0) {
            throw new IllegalArgumentException("StartAddress must be non-negative: " + startAddress);
        }
        if (size < 0) {
            throw new IllegalArgumentException("Size must be non-negative: " + size);
        }
    }
}
