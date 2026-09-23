package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.Objects;

/** Resolved symbol evidence; provenance identifies the symbol or signature pack. */
public record EspSymbolFact(
        String name, long address, EspSymbolFactKind kind, String provenance) {
    public EspSymbolFact {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(provenance, "provenance");
        if (name.isBlank() || provenance.isBlank() || address < 0) {
            throw new IllegalArgumentException("Invalid ESP symbol fact");
        }
    }
}
