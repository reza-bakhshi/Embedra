package io.github.rezabakhshi.embedra.analyzers.nordic;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Recorded per-program evidence required before any Nordic signature is applied (NRF-009, NRF-010).
 *
 * <p>Series and exact part identity are verified caller facts. When absent, the matcher
 * returns an explicit {@code EVIDENCE_MISSING} non-match and avoids guessed symbol applications.</p>
 */
public record NordicSignatureContext(
        String exactPart,
        String series,
        Optional<String> compiler,
        Optional<String> optimization,
        List<NordicFunctionBytes> functions) {

    public NordicSignatureContext {
        exactPart = requireText(exactPart, "exactPart");
        series = requireText(series, "series");
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
