package io.github.rezabakhshi.embedra.analyzers.stm8;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Recorded per-program evidence required before any STM8 signature is applied (STM8-009).
 *
 * <p>Compiler identity and device family are caller-recorded facts. When absent, the matcher
 * returns an explicit {@code EVIDENCE_MISSING} non-match and avoids guessed symbol applications.</p>
 */
public record Stm8SignatureContext(
        String exactPart,
        String family,
        Optional<String> compiler,
        Optional<String> memoryModel,
        List<Stm8FunctionBytes> functions) {

    public Stm8SignatureContext {
        exactPart = requireText(exactPart, "exactPart");
        family = Objects.requireNonNull(family, "family");
        compiler = Objects.requireNonNull(compiler, "compiler");
        memoryModel = Objects.requireNonNull(memoryModel, "memoryModel");
        compiler.ifPresent(value -> requireText(value, "compiler"));
        memoryModel.ifPresent(value -> requireText(value, "memoryModel"));
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
