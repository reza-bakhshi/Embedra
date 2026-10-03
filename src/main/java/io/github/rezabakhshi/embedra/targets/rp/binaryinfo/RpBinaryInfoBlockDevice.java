package io.github.rezabakhshi.embedra.targets.rp.binaryinfo;

import java.util.Objects;

/**
 * Parsed block device descriptor from a Pico SDK binary info block.
 */
public record RpBinaryInfoBlockDevice(
        String name,
        long address,
        long size,
        int flags) {

    public RpBinaryInfoBlockDevice {
        Objects.requireNonNull(name, "name must not be null");
    }
}
