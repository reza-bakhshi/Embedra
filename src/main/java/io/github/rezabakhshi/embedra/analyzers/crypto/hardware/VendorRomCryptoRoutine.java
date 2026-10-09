package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import java.util.Objects;

/**
 * Immutable definition of a vendor ROM cryptographic routine entry (AN-010, AN-013).
 *
 * @param routineId unique identifier (e.g. "rp2040-rom-flash-erase", "esp32s3-rom-sha256")
 * @param routineName human-readable function name (e.g. "ets_sha_enable", "rom_flash_erase")
 * @param platform target hardware platform
 * @param address exact entry point address, or -1 if resolved dynamically via lookup table
 * @param lookupCode 2-character RP2040 lookup code (e.g. "RE") or null if direct
 * @param algorithm associated cryptographic or security algorithm
 * @param feature hardware feature category
 * @param description documentation explaining routine purpose and parameters
 */
public record VendorRomCryptoRoutine(
        String routineId,
        String routineName,
        HardwareCryptoPlatform platform,
        long address,
        String lookupCode,
        CryptoAlgorithm algorithm,
        HardwareCryptoFeature feature,
        String description) {

    public VendorRomCryptoRoutine {
        Objects.requireNonNull(routineId, "routineId must not be null");
        Objects.requireNonNull(routineName, "routineName must not be null");
        Objects.requireNonNull(platform, "platform must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(feature, "feature must not be null");
        Objects.requireNonNull(description, "description must not be null");
    }
}
