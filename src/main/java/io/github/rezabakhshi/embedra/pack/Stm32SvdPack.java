package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.svd.Stm32SvdDevice;
import java.util.Objects;

/** Integrity-checked STM32 CMSIS-SVD device pack and its exact source provenance. */
public record Stm32SvdPack(
        PackManifest manifest,
        Stm32SvdDevice device,
        String cpu,
        String sourceFile,
        String sourceFileSha256) {
    public Stm32SvdPack {
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(sourceFile, "sourceFile");
        Objects.requireNonNull(sourceFileSha256, "sourceFileSha256");
        if (!sourceFileSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("SVD source digest must be lowercase SHA-256");
        }
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
