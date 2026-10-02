package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable inputs for one bounded STM32 CTF enrichment pass.
 *
 * <p>The context reuses the shared contracts unchanged: confirmed
 * {@link Stm32FirmwareArtifact} records (the same inputs the T048 diff
 * consumes), bounded candidate function bytes for the T043 evidence-gated
 * matcher, the caller-recorded STM-012 build evidence (family, compiler,
 * optimization — never derived here), an optional digest-pinned T044 security
 * record, and the exact-part membership of the digest-pinned curated selection.
 * Structural ambiguity — duplicate artifact ids or roles, duplicate candidate
 * function addresses, or a candidate address beyond the 32-bit space — is
 * rejected here; binding and availability stay typed diagnostics of
 * {@link Stm32CtfEnrichmentAnalyzer}.</p>
 */
public record Stm32CtfEnrichmentContext(
        Stm32PartSelection selection,
        List<Stm32FirmwareArtifact> artifacts,
        List<Stm32FunctionBytes> functions,
        Optional<String> family,
        Optional<String> compiler,
        Optional<String> optimization,
        Optional<Stm32SecurityRecord> security) {

    private static final long ADDRESS_SPACE_END = 0x1_0000_0000L;

    public Stm32CtfEnrichmentContext {
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(family, "family");
        Objects.requireNonNull(compiler, "compiler");
        Objects.requireNonNull(optimization, "optimization");
        Objects.requireNonNull(security, "security");
        artifacts = List.copyOf(artifacts);
        functions = List.copyOf(functions);
        if (artifacts.isEmpty()) {
            throw new IllegalArgumentException("At least one confirmed artifact is required");
        }
        validateOptionalText(family, "Family");
        validateOptionalText(compiler, "Compiler");
        validateOptionalText(optimization, "Optimization");
        Set<String> ids = new HashSet<>();
        Set<Stm32FirmwareRole> roles = EnumSet.noneOf(Stm32FirmwareRole.class);
        for (Stm32FirmwareArtifact artifact : artifacts) {
            if (!ids.add(artifact.id())) {
                throw new IllegalArgumentException("Duplicate confirmed artifact id: "
                    + artifact.id());
            }
            if (!roles.add(artifact.role())) {
                throw new IllegalArgumentException(
                    "Duplicate confirmed artifact role: " + artifact.role());
            }
        }
        Set<Long> addresses = new HashSet<>();
        for (Stm32FunctionBytes function : functions) {
            if (function.address() >= ADDRESS_SPACE_END) {
                throw new IllegalArgumentException(
                    "Candidate function address is outside the 32-bit space: "
                        + function.address());
            }
            if (!addresses.add(function.address())) {
                throw new IllegalArgumentException("Duplicate candidate function address: "
                    + function.address());
            }
        }
    }

    private static void validateOptionalText(Optional<String> value, String label) {
        if (value.filter(String::isBlank).isPresent()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
    }
}
