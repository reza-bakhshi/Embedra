package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** Immutable common and extended ESP application-image header. */
public record EspImageHeader(
        int magic,
        int segmentCount,
        int flashMode,
        int flashSizeFrequency,
        long entryPoint,
        int writeProtectPin,
        int clockDriveStrength,
        int qDriveStrength,
        int dDriveStrength,
        int csDriveStrength,
        int hdDriveStrength,
        int wpDriveStrength,
        int chipId,
        int minimumRevision,
        int minimumRevisionFull,
        int maximumRevisionFull,
        boolean digestAppended,
        SourceRange sourceRange) {
    public EspImageHeader {
        Objects.requireNonNull(sourceRange, "sourceRange");
        if (magic != EspImageDetector.MAGIC || segmentCount <= 0
            || segmentCount > EspImageDetector.MAX_SEGMENTS) {
            throw new IllegalArgumentException("Invalid ESP image header model");
        }
    }
}
