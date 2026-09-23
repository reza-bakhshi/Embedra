package io.github.rezabakhshi.embedra.ghidra.esp;

import java.util.List;

/** Result of receipt-scoped enrichment removal. */
public record EspPackRemovalReport(
        boolean committed,
        int removedBlocks,
        int removedSymbols,
        int removedData,
        List<EspPackConflict> conflicts) {
    public EspPackRemovalReport {
        if (removedBlocks < 0 || removedSymbols < 0 || removedData < 0) {
            throw new IllegalArgumentException("Removal counts must be non-negative");
        }
        conflicts = List.copyOf(conflicts);
    }
}
