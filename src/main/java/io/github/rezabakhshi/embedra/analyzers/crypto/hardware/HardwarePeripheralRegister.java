package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable definition of a hardware cryptographic peripheral register mapping (AN-013).
 *
 * @param registerId unique ID within platform (e.g. "esp32s3-aes-mode")
 * @param peripheralName high-level peripheral block name (e.g. "AES", "CRYP", "SHA")
 * @param platform target hardware platform
 * @param address physical memory-mapped register address
 * @param sizeBytes register width in bytes (typically 4)
 * @param algorithm associated cryptographic algorithm
 * @param feature hardware feature category
 * @param triggerRegister whether writing to this register activates a hardware operation
 * @param modeMapping optional mapping from written integer values to specific algorithm modes
 * @param description human-readable explanation
 */
public record HardwarePeripheralRegister(
        String registerId,
        String peripheralName,
        HardwareCryptoPlatform platform,
        long address,
        int sizeBytes,
        CryptoAlgorithm algorithm,
        HardwareCryptoFeature feature,
        boolean triggerRegister,
        Map<Long, String> modeMapping,
        String description) {

    public HardwarePeripheralRegister {
        Objects.requireNonNull(registerId, "registerId must not be null");
        Objects.requireNonNull(peripheralName, "peripheralName must not be null");
        Objects.requireNonNull(platform, "platform must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(feature, "feature must not be null");
        Objects.requireNonNull(description, "description must not be null");
        if (address < 0) {
            throw new IllegalArgumentException("Address must be non-negative: " + address);
        }
        if (sizeBytes <= 0) {
            throw new IllegalArgumentException("sizeBytes must be positive: " + sizeBytes);
        }
        modeMapping = modeMapping == null ? Map.of() : Collections.unmodifiableMap(Map.copyOf(modeMapping));
    }
}
