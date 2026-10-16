package io.github.rezabakhshi.embedra.analyzers.atmel;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Recorded per-program evidence required before any Atmel/Microchip runtime signature is applied.
 *
 * <p>Series, exact part, and architecture identity are verified caller facts. When absent, the matcher
 * returns an explicit {@code EVIDENCE_MISSING} non-match and avoids guessed symbol applications.</p>
 */
public record AtmelSignatureContext(
        String exactPart,
        String series,
        String architecture,
        Optional<String> compiler,
        Optional<String> optimization,
        List<AtmelFunctionBytes> functions) {

    public AtmelSignatureContext {
        exactPart = requireText(exactPart, "exactPart");
        series = requireText(series, "series");
        architecture = requireText(architecture, "architecture");
        compiler = Objects.requireNonNull(compiler, "compiler");
        optimization = Objects.requireNonNull(optimization, "optimization");
        compiler.ifPresent(value -> requireText(value, "compiler"));
        optimization.ifPresent(value -> requireText(value, "optimization"));
        functions = List.copyOf(functions);
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
