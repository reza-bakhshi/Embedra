package io.github.rezabakhshi.embedra.ghidra.stm32;

import java.util.List;
import java.util.Objects;

/** Transaction receipt for one provenance-checked STM32 device-data application. */
public record Stm32DeviceDataReport(
        boolean committed,
        String exactPart,
        String core,
        String packId,
        String contentDigest,
        String sourceFile,
        String sourceFileSha256,
        List<Block> createdBlocks,
        List<Symbol> createdSymbols,
        List<Long> createdDataAddresses,
        int createdComments,
        int createdEnumerations,
        int registerCount,
        int interruptCount,
        List<Conflict> conflicts) {
    public Stm32DeviceDataReport {
        Objects.requireNonNull(exactPart, "exactPart");
        createdBlocks = List.copyOf(createdBlocks);
        createdSymbols = List.copyOf(createdSymbols);
        createdDataAddresses = List.copyOf(createdDataAddresses);
        conflicts = List.copyOf(conflicts);
        if (createdComments < 0 || createdEnumerations < 0 || registerCount < 0
            || interruptCount < 0) {
            throw new IllegalArgumentException("Report counts must not be negative");
        }
    }

    public record Block(String name, long address, long length) {
        public Block {
            Objects.requireNonNull(name, "name");
            if (address < 0 || length <= 0) {
                throw new IllegalArgumentException("Created block is invalid");
            }
        }
    }

    public record Symbol(String name, long address) {
        public Symbol {
            Objects.requireNonNull(name, "name");
            if (address < 0) {
                throw new IllegalArgumentException("Applied symbol is invalid");
            }
        }
    }

    public record Conflict(long address, String kind, String detail) {
        public Conflict {
            if (address < 0 || address > 0xffff_ffffL) {
                throw new IllegalArgumentException("Conflict address is invalid");
            }
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(detail, "detail");
        }
    }
}
