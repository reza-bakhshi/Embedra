package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.svd.EspSvdDevice;
import java.util.Objects;

/** Integrity-checked ESP32-S3 SVD pack and its cross-source evidence. */
public record EspSvdPack(
        PackManifest manifest,
        EspSvdDevice device,
        EspSvdReconciliation reconciliation) {
    public EspSvdPack {
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(reconciliation, "reconciliation");
    }

    public long registerCount() {
        return device.peripherals().stream()
            .mapToLong(peripheral -> peripheral.registers().size()).sum();
    }

    public long fieldCount() {
        return device.peripherals().stream().flatMap(peripheral ->
            peripheral.registers().stream()).mapToLong(register ->
                register.fields().size()).sum();
    }
}
