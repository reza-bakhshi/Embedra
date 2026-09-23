package io.github.rezabakhshi.embedra.ghidra.esp;

import java.util.List;
import java.util.Objects;

/** Transaction receipt for one provenance-checked SVD application. */
public record EspSvdApplicationReport(
        boolean committed,
        String svdContentDigest,
        List<EspCreatedBlock> createdBlocks,
        List<EspAppliedSymbol> createdSymbols,
        List<Long> createdDataAddresses,
        int createdComments,
        List<EspPackConflict> conflicts) {
    public EspSvdApplicationReport {
        Objects.requireNonNull(svdContentDigest, "svdContentDigest");
        createdBlocks = List.copyOf(createdBlocks);
        createdSymbols = List.copyOf(createdSymbols);
        createdDataAddresses = List.copyOf(createdDataAddresses);
        if (createdComments < 0) {
            throw new IllegalArgumentException("Created comment count must not be negative");
        }
        conflicts = List.copyOf(conflicts);
    }
}
