package io.github.rezabakhshi.embedra.ghidra.stm8;

import java.util.Objects;

/**
 * Immutable audit report recording the results of an STM8 firmware import into Ghidra.
 */
public record Stm8ImportReport(
        String exactPart,
        String family,
        String inputFormat,
        String languageId,
        String compilerSpecId,
        long entryPoint,
        long flashBase,
        long flashBytes,
        int blocksCreated,
        int vectorsApplied,
        int registersApplied,
        boolean success,
        String notes) {

    public Stm8ImportReport {
        Objects.requireNonNull(exactPart, "exactPart must not be null");
        Objects.requireNonNull(family, "family must not be null");
        Objects.requireNonNull(inputFormat, "inputFormat must not be null");
        Objects.requireNonNull(languageId, "languageId must not be null");
        Objects.requireNonNull(compilerSpecId, "compilerSpecId must not be null");
        notes = notes == null ? "" : notes;
    }
}
