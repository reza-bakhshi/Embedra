package io.github.rezabakhshi.embedra.formats.esp.layout;

import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCpuIsa;
import java.util.Objects;

/**
 * Immutable per-target flash layout characteristics and boundaries.
 */
public record EspFlashLayoutProfile(
        String series,
        int chipId,
        String displayName,
        EspCpuIsa isa,
        String defaultLanguageId,
        String defaultCompilerSpecId,
        long bootloaderOffset,
        long minBootloaderLength,
        long maxBootloaderLength,
        long defaultPartitionTableOffset,
        long minPartitionTableOffset,
        long maxPartitionTableOffset,
        int mmuPageSize,
        long maxSupportedFlashSize,
        String referenceSource
) {
    public EspFlashLayoutProfile {
        Objects.requireNonNull(series, "series");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(isa, "isa");
        Objects.requireNonNull(defaultLanguageId, "defaultLanguageId");
        Objects.requireNonNull(defaultCompilerSpecId, "defaultCompilerSpecId");
        Objects.requireNonNull(referenceSource, "referenceSource");
        if (bootloaderOffset < 0 || defaultPartitionTableOffset <= bootloaderOffset) {
            throw new IllegalArgumentException("Invalid layout offsets for " + series);
        }
        if (minPartitionTableOffset < 0 || maxPartitionTableOffset < minPartitionTableOffset) {
            throw new IllegalArgumentException("Invalid partition table bounds for " + series);
        }
    }
}
