package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable aggregated snapshot of a firmware workspace for multi-view diffing (T062).
 *
 * @param workspaceName workspace or program identifier
 * @param functions list of disassembled functions
 * @param symbols list of program symbols
 * @param strings list of discovered string literals
 * @param metadata list of workspace metadata properties
 * @param memoryBlocks list of mapped memory blocks
 * @param partitions list of partitions or flash containers
 */
public record WorkspaceSnapshot(
        String workspaceName,
        List<FunctionSnapshot> functions,
        List<SymbolSnapshot> symbols,
        List<StringSnapshot> strings,
        List<MetadataSnapshot> metadata,
        List<MemoryBlockSnapshot> memoryBlocks,
        List<PartitionSnapshot> partitions) {

    public WorkspaceSnapshot {
        Objects.requireNonNull(workspaceName, "workspaceName must not be null");
        functions = functions == null ? List.of() : Collections.unmodifiableList(List.copyOf(functions));
        symbols = symbols == null ? List.of() : Collections.unmodifiableList(List.copyOf(symbols));
        strings = strings == null ? List.of() : Collections.unmodifiableList(List.copyOf(strings));
        metadata = metadata == null ? List.of() : Collections.unmodifiableList(List.copyOf(metadata));
        memoryBlocks = memoryBlocks == null ? List.of() : Collections.unmodifiableList(List.copyOf(memoryBlocks));
        partitions = partitions == null ? List.of() : Collections.unmodifiableList(List.copyOf(partitions));
    }

    public static WorkspaceSnapshot empty(String workspaceName) {
        return new WorkspaceSnapshot(workspaceName, List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }
}
