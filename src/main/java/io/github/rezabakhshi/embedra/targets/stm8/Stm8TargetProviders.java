package io.github.rezabakhshi.embedra.targets.stm8;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Registry and factory for pure STM8 family target providers.
 */
public final class Stm8TargetProviders {

    private static final Stm8sTargetProvider STM8S = new Stm8sTargetProvider();

    private static final Stm8lTargetProvider STM8L = new Stm8lTargetProvider();

    private static final Stm8aTargetProvider STM8A = new Stm8aTargetProvider();

    private static final Stm8tTargetProvider STM8T = new Stm8tTargetProvider();

    private static final List<Stm8TargetProvider> ALL = List.of(STM8S, STM8L, STM8A, STM8T);

    private Stm8TargetProviders() {
    }

    public static List<Stm8TargetProvider> all() {
        return ALL;
    }

    public static Optional<Stm8TargetProvider> forFamily(String family) {
        if (family == null || family.isBlank()) {
            return Optional.empty();
        }
        String f = family.trim().toUpperCase(Locale.ROOT);
        if (f.equals("STM8S")) {
            return Optional.of(STM8S);
        }
        if (f.equals("STM8L")) {
            return Optional.of(STM8L);
        }
        if (f.equals("STM8A") || f.equals("STM8AF") || f.equals("STM8AL")) {
            return Optional.of(STM8A);
        }
        if (f.equals("STM8T")) {
            return Optional.of(STM8T);
        }
        return Optional.empty();
    }

    public static Optional<Stm8TargetProvider> forPart(Stm8PartRecord part) {
        if (part == null) {
            return Optional.empty();
        }
        for (Stm8TargetProvider provider : ALL) {
            if (provider.supports(part).supported()) {
                return Optional.of(provider);
            }
        }
        return Optional.empty();
    }

    public static Stm8TargetProvider getRequiredProvider(String family) throws DiagnosticException {
        return forFamily(family).orElseThrow(() -> new DiagnosticException(Diagnostic.error(
            DiagnosticCode.STM8_TARGET_UNSUPPORTED,
            "No STM8 target provider available for family: " + family,
            null)));
    }

    public static Stm8TargetProvider getRequiredProvider(Stm8PartRecord part) throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        return forPart(part).orElseThrow(() -> new DiagnosticException(Diagnostic.error(
            DiagnosticCode.STM8_TARGET_UNSUPPORTED,
            "No STM8 target provider supports exact part: " + part.exactPart(),
            null)));
    }
}
