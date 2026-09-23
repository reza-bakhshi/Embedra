package io.github.rezabakhshi.embedra.pack;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Verified immutable ESP ROM symbol pack content. */
public final class EspRomSymbolPack {
    private final PackManifest manifest;

    private final String deviceId;

    private final List<EspRomSymbol> symbols;

    private final Map<String, EspRomSymbol> byName;

    public EspRomSymbolPack(PackManifest manifest, String deviceId,
            List<EspRomSymbol> symbols) {
        this.manifest = Objects.requireNonNull(manifest, "manifest");
        PackManifest.requireIdentifier(deviceId, "device ID");
        this.deviceId = deviceId;
        this.symbols = List.copyOf(symbols);
        if (this.symbols.isEmpty()) {
            throw new IllegalArgumentException("ROM symbol pack must not be empty");
        }
        Map<String, EspRomSymbol> indexed = new HashMap<>();
        for (EspRomSymbol symbol : this.symbols) {
            if (indexed.put(symbol.name(), symbol) != null) {
                throw new IllegalArgumentException("Duplicate ROM symbol name");
            }
        }
        byName = Map.copyOf(indexed);
    }

    public PackManifest manifest() {
        return manifest;
    }

    public String deviceId() {
        return deviceId;
    }

    public List<EspRomSymbol> symbols() {
        return symbols;
    }

    public EspRomSymbol requireSymbol(String name) {
        EspRomSymbol symbol = byName.get(name);
        if (symbol == null) {
            throw new IllegalArgumentException("Unknown ROM symbol: " + name);
        }
        return symbol;
    }
}
