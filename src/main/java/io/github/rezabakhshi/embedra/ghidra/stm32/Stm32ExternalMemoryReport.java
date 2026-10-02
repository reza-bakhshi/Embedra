package io.github.rezabakhshi.embedra.ghidra.stm32;

import java.util.List;
import java.util.Objects;

/** Transaction receipt for one external-memory window mapping or byte load. */
public record Stm32ExternalMemoryReport(
        boolean committed,
        String exactPart,
        String operation,
        String source,
        List<Block> createdBlocks,
        List<Symbol> createdSymbols,
        List<Conflict> conflicts,
        long loadedByteCount) {
    public Stm32ExternalMemoryReport {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(source, "source");
        createdBlocks = List.copyOf(createdBlocks);
        createdSymbols = List.copyOf(createdSymbols);
        conflicts = List.copyOf(conflicts);
        if (loadedByteCount < 0) {
            throw new IllegalArgumentException("Loaded byte count must not be negative");
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
