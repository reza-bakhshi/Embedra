package io.github.rezabakhshi.embedra.analyzers.stm32;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Recorded per-program evidence required before any STM32 signature is applied.
 *
 * <p>Compiler identity, optimization level, and device family are explicit,
 * caller-recorded facts (STM-012). When any of them is absent, the matcher
 * returns an explicit {@code EVIDENCE_MISSING} non-match and scans nothing.
 * Candidate function byte regions are bounded by the shared parser limits.</p>
 */
public record Stm32SignatureContext(
        String exactPart,
        String family,
        Optional<String> compiler,
        Optional<String> optimization,
        List<Stm32FunctionBytes> functions) {
    public Stm32SignatureContext {
        exactPart = requireText(exactPart, "exactPart");
        family = Objects.requireNonNull(family, "family");
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
