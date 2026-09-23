package io.github.rezabakhshi.embedra.ghidra.esp;

import java.util.Objects;

/** Deterministic non-destructive merge conflict from pack application/removal. */
public record EspPackConflict(long address, String kind, String detail) {
    public EspPackConflict {
        if (address < 0 || address > 0xffff_ffffL) {
            throw new IllegalArgumentException("Conflict address is invalid");
        }
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(detail, "detail");
    }
}
