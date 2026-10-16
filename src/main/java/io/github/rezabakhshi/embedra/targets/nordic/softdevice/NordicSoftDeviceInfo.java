package io.github.rezabakhshi.embedra.targets.nordic.softdevice;

import java.util.Objects;

/**
 * Immutable metadata representing a discovered Nordic SoftDevice and MBR firmware layout.
 */
public record NordicSoftDeviceInfo(
        NordicSoftDeviceType type,
        String versionString,
        int firmwareId,
        long softDeviceOffset,
        long softDeviceSizeBytes,
        long applicationOffset,
        boolean mbrPresent,
        long mbrSizeBytes,
        long svcHandlerAddress) {

    public NordicSoftDeviceInfo {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(versionString, "versionString must not be null");
        if (softDeviceOffset < 0 || softDeviceSizeBytes < 0 || applicationOffset < 0) {
            throw new IllegalArgumentException("Offsets and sizes must be non-negative");
        }
    }

    public long totalReservedFlash() {
        return applicationOffset;
    }
}
