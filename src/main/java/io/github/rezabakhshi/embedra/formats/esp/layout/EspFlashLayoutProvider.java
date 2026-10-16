package io.github.rezabakhshi.embedra.formats.esp.layout;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;

/**
 * Pure contract for ESP target-specific flash layouts and image validation.
 */
public interface EspFlashLayoutProvider {
    /** Unique identifier for the provider (typically matches target series in lower-case). */
    String providerId();

    /** Immutable layout profile for this target. */
    EspFlashLayoutProfile profile();

    /** Chip ID assigned to this target by Espressif. */
    default int chipId() {
        return profile().chipId();
    }

    /** Bootloader starting offset in flash bytes. */
    default long bootloaderOffset() {
        return profile().bootloaderOffset();
    }

    /** Default partition table offset in flash bytes (typically 0x8000). */
    default long defaultPartitionTableOffset() {
        return profile().defaultPartitionTableOffset();
    }

    /** Returns true if the given chip ID matches this provider. */
    default boolean matchesChipId(int chipId) {
        return profile().chipId() == chipId;
    }

    /** Checks whether a candidate bootloader offset is valid for this target. */
    default boolean isValidBootloaderOffset(long offset) {
        return offset == profile().bootloaderOffset();
    }

    /** Checks whether a candidate partition table offset is within valid bounds. */
    default boolean isValidPartitionTableOffset(long offset) {
        return offset >= profile().minPartitionTableOffset()
                && offset <= profile().maxPartitionTableOffset()
                && (offset % 0x1000) == 0;
    }

    /** Validates a parsed bootloader image against target rules. */
    void validateBootloader(EspImage bootloader) throws DiagnosticException;

    /** Validates a parsed application image against target rules. */
    void validateApplication(EspImage application) throws DiagnosticException;
}
