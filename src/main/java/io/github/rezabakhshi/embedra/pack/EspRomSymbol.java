package io.github.rezabakhshi.embedra.pack;

import java.util.List;
import java.util.Objects;

/** One provenance-bearing ESP ROM symbol. */
public record EspRomSymbol(
        String name,
        long address,
        EspRomSymbolKind kind,
        List<String> sourceFiles) {
    public EspRomSymbol {
        PackManifest.requireIdentifier(name, "ROM symbol name");
        if (address < 0 || address > 0xffff_ffffL) {
            throw new IllegalArgumentException("ROM symbol address is not unsigned 32-bit");
        }
        Objects.requireNonNull(kind, "kind");
        sourceFiles = List.copyOf(sourceFiles);
        if (sourceFiles.isEmpty()) {
            throw new IllegalArgumentException("ROM symbol source files must not be empty");
        }
    }
}
