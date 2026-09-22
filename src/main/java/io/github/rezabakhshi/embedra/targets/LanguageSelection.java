package io.github.rezabakhshi.embedra.targets;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Exact Ghidra language/compiler choice with retained selection evidence. */
public record LanguageSelection(
        String languageId,
        String compilerSpecId,
        String instructionSet,
        int addressSizeBits,
        int instructionAlignmentBytes,
        String endianness,
        List<Evidence> evidence) {
    public LanguageSelection {
        Objects.requireNonNull(languageId, "languageId");
        Objects.requireNonNull(compilerSpecId, "compilerSpecId");
        Objects.requireNonNull(instructionSet, "instructionSet");
        Objects.requireNonNull(endianness, "endianness");
        evidence = List.copyOf(evidence);
        if (languageId.isBlank() || compilerSpecId.isBlank() || instructionSet.isBlank()
            || endianness.isBlank() || addressSizeBits <= 0 || instructionAlignmentBytes <= 0
            || evidence.isEmpty()) {
            throw new IllegalArgumentException("Language selection must be complete and evidenced");
        }
    }
}
