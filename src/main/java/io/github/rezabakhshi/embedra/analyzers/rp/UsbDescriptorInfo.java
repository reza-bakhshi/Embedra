package io.github.rezabakhshi.embedra.analyzers.rp;

import java.util.Objects;

/**
 * Information about a detected USB descriptor.
 */
public record UsbDescriptorInfo(
        long address,
        String type,
        int length,
        String description) {

    public UsbDescriptorInfo {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(description, "description must not be null");
    }
}
