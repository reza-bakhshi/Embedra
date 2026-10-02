package io.github.rezabakhshi.embedra.ghidra.stm32;

import java.util.List;
import java.util.Objects;

/** Transaction receipt for one confirmed STM32 vector-label application. */
public record Stm32VectorApplicationReport(
        boolean committed,
        String exactPart,
        long tableAddress,
        String sourceDigest,
        String confirmationMethod,
        int vectorSlotCount,
        int namedSlotCount,
        int resolvedHandlerCount,
        int createdLabelCount,
        int createdFunctionCount,
        int aliasedSlotCount,
        List<Symbol> createdSymbols,
        List<Long> createdFunctionAddresses,
        List<Conflict> conflicts,
        List<Diagnostic> diagnostics) {
    public Stm32VectorApplicationReport {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(confirmationMethod, "confirmationMethod");
        createdSymbols = List.copyOf(createdSymbols);
        createdFunctionAddresses = List.copyOf(createdFunctionAddresses);
        conflicts = List.copyOf(conflicts);
        diagnostics = List.copyOf(diagnostics);
        if (tableAddress < 0 || tableAddress > 0xffff_ffffL) {
            throw new IllegalArgumentException("Vector table address is invalid");
        }
        if (vectorSlotCount < 0 || namedSlotCount < 0 || resolvedHandlerCount < 0
                || createdLabelCount < 0 || createdFunctionCount < 0 || aliasedSlotCount < 0) {
            throw new IllegalArgumentException("Report counts must not be negative");
        }
    }

    /** One label created by this application. */
    public record Symbol(String name, long address, boolean function) {
        public Symbol {
            Objects.requireNonNull(name, "name");
            if (address < 0 || address > 0xffff_ffffL) {
                throw new IllegalArgumentException("Applied symbol is invalid");
            }
        }
    }

    /** One preserved or unresolved artifact at a vector slot or handler address. */
    public record Conflict(long address, String kind, String detail) {
        public Conflict {
            if (address < 0 || address > 0xffff_ffffL) {
                throw new IllegalArgumentException("Conflict address is invalid");
            }
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(detail, "detail");
        }
    }

    /** One explicit plan-level diagnostic. */
    public record Diagnostic(String code, String detail) {
        public Diagnostic {
            Objects.requireNonNull(code, "code");
            Objects.requireNonNull(detail, "detail");
        }
    }
}
