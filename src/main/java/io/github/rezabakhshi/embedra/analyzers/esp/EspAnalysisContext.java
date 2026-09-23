package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.formats.esp.EspAppDescription;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Immutable facts extracted from a program before ESP-IDF enrichment. */
public record EspAnalysisContext(
        String deviceId,
        String idfVersion,
        String toolchain,
        String optimization,
        Optional<EspAppDescription> appDescription,
        List<EspStringFact> strings,
        List<EspSymbolFact> symbols,
        List<EspCallFact> calls,
        List<EspFunctionFact> functions) {
    public EspAnalysisContext {
        requireText(deviceId, "deviceId");
        requireText(idfVersion, "idfVersion");
        requireText(toolchain, "toolchain");
        requireText(optimization, "optimization");
        Objects.requireNonNull(appDescription, "appDescription");
        strings = List.copyOf(strings);
        symbols = List.copyOf(symbols);
        calls = List.copyOf(calls);
        functions = List.copyOf(functions);
    }

    private static void requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
