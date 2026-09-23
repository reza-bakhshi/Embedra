package io.github.rezabakhshi.embedra.ghidra.esp;

import java.util.Objects;

/** One symbol created from a verified enrichment pack. */
public record EspAppliedSymbol(String name, long address, boolean function) {
    public EspAppliedSymbol {
        Objects.requireNonNull(name, "name");
        if (name.isBlank() || address < 0 || address > 0xffff_ffffL) {
            throw new IllegalArgumentException("Applied symbol is invalid");
        }
    }
}
