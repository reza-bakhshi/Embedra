package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import java.util.List;
import java.util.Objects;

/** Immutable all-or-nothing workspace plan for one validated ESP full-flash image. */
public record EspFullFlashWorkspace(
        EspPartitionTable partitionTable,
        List<EspExtractedExecutable> executables,
        List<EspExtractedPartition> dataPartitions,
        ProgramStrategy programStrategy,
        String sourceSha256,
        EspPartitionAnalysis partitionAnalysis) {
    public EspFullFlashWorkspace {
        Objects.requireNonNull(partitionTable, "partitionTable");
        executables = List.copyOf(executables);
        dataPartitions = List.copyOf(dataPartitions);
        Objects.requireNonNull(programStrategy, "programStrategy");
        Objects.requireNonNull(sourceSha256, "sourceSha256");
        Objects.requireNonNull(partitionAnalysis, "partitionAnalysis");
        if (executables.isEmpty() || programStrategy != ProgramStrategy.SEPARATE_PROGRAMS
            || executables.stream().map(EspExtractedExecutable::name).distinct().count()
                != executables.size() || !sourceSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid ESP full-flash workspace");
        }
    }
}
