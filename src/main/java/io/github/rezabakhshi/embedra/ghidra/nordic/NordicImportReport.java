package io.github.rezabakhshi.embedra.ghidra.nordic;

import java.util.Objects;

/**
 * Immutable report detailing the outcome of a Nordic firmware import operation into Ghidra.
 */
public record NordicImportReport(
    String exactPart,
    String series,
    String format,
    String languageId,
    String compilerSpec,
    long entryPoint,
    long flashBase,
    long flashBytes,
    int blocksCreated,
    int registersApplied,
    boolean success,
    String message
) {

    public NordicImportReport {
        Objects.requireNonNull(exactPart, "exactPart must not be null");
        Objects.requireNonNull(series, "series must not be null");
        Objects.requireNonNull(format, "format must not be null");
        Objects.requireNonNull(languageId, "languageId must not be null");
        Objects.requireNonNull(compilerSpec, "compilerSpec must not be null");
        Objects.requireNonNull(message, "message must not be null");
    }
}
