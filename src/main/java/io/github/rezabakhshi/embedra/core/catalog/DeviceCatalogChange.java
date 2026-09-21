package io.github.rezabakhshi.embedra.core.catalog;

import java.util.Objects;

/** Before/after value for one changed exact-device record. */
public record DeviceCatalogChange(
        String deviceId, DeviceCatalogEntry previous, DeviceCatalogEntry current) {
    public DeviceCatalogChange {
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(previous, "previous");
        Objects.requireNonNull(current, "current");
        if (!deviceId.equals(previous.deviceId()) || !deviceId.equals(current.deviceId())) {
            throw new IllegalArgumentException("Catalog change records must share their device ID");
        }
        if (previous.equals(current)) {
            throw new IllegalArgumentException("Catalog change must contain different records");
        }
    }
}
