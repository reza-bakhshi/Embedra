package io.github.rezabakhshi.embedra.ghidra.esp;

import java.util.List;
import java.util.Objects;

/** Immutable receipt required for safe, targeted pack removal. */
public record EspPackApplicationReport(
        boolean committed,
        String romContentDigest,
        String peripheralContentDigest,
        List<EspCreatedBlock> createdBlocks,
        List<EspAppliedSymbol> createdSymbols,
        List<Long> createdDataAddresses,
        List<EspPackConflict> conflicts) {
    public EspPackApplicationReport {
        Objects.requireNonNull(romContentDigest, "romContentDigest");
        Objects.requireNonNull(peripheralContentDigest, "peripheralContentDigest");
        createdBlocks = List.copyOf(createdBlocks);
        createdSymbols = List.copyOf(createdSymbols);
        createdDataAddresses = List.copyOf(createdDataAddresses);
        conflicts = List.copyOf(conflicts);
    }
}
