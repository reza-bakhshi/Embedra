package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Immutable snapshot of a partition or flash segment for workspace diffing (T062).
 *
 * @param name partition label or identifier
 * @param type partition category type (e.g. "app", "data", "bootloader")
 * @param subtype partition subtype (e.g. "factory", "ota_0", "nvs", "spiffs")
 * @param offset physical or flash offset
 * @param size byte length of the partition
 * @param flags flags or attributes (e.g. "encrypted")
 */
public record PartitionSnapshot(
        String name,
        String type,
        String subtype,
        long offset,
        long size,
        String flags) {

    public PartitionSnapshot {
        Objects.requireNonNull(name, "name must not be null");
        type = type == null ? "data" : type;
        subtype = subtype == null ? "" : subtype;
        flags = flags == null ? "" : flags;
        if (offset < 0) {
            throw new IllegalArgumentException("Offset must be non-negative: " + offset);
        }
        if (size < 0) {
            throw new IllegalArgumentException("Size must be non-negative: " + size);
        }
    }
}
