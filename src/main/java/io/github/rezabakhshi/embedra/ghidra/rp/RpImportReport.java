package io.github.rezabakhshi.embedra.ghidra.rp;

import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadata;
import java.util.Objects;

/**
 * Report produced upon successful import and mapping of Raspberry Pi firmware into Ghidra.
 */
public record RpImportReport(
        String series,
        String targetPart,
        String containerFormat,
        String languageId,
        String compilerSpecId,
        int mappedSegmentsCount,
        long entryPoint,
        RpBootMetadata bootMetadata) {

    public RpImportReport {
        Objects.requireNonNull(series, "series must not be null");
        Objects.requireNonNull(targetPart, "targetPart must not be null");
        Objects.requireNonNull(containerFormat, "containerFormat must not be null");
        Objects.requireNonNull(languageId, "languageId must not be null");
        Objects.requireNonNull(compilerSpecId, "compilerSpecId must not be null");
        Objects.requireNonNull(bootMetadata, "bootMetadata must not be null");
    }
}
