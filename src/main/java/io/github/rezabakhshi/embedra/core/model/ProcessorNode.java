package io.github.rezabakhshi.embedra.core.model;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Immutable description of a physical, logical, or programmable execution unit. */
public record ProcessorNode(
        String id,
        ProcessorKind kind,
        Optional<String> instructionSet,
        Optional<String> ghidraLanguageId,
        Optional<String> compilerSpecId,
        String role,
        SecurityDomain securityDomain,
        String ownership,
        Set<String> addressSpaces,
        List<ResetEntry> resetEntries,
        FirmwareSource firmwareSource,
        Confidence confidence,
        List<Evidence> evidence) {
    public ProcessorNode {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(instructionSet, "instructionSet");
        Objects.requireNonNull(ghidraLanguageId, "ghidraLanguageId");
        Objects.requireNonNull(compilerSpecId, "compilerSpecId");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(securityDomain, "securityDomain");
        Objects.requireNonNull(ownership, "ownership");
        Objects.requireNonNull(firmwareSource, "firmwareSource");
        Objects.requireNonNull(confidence, "confidence");
        addressSpaces = Set.copyOf(addressSpaces);
        resetEntries = List.copyOf(resetEntries);
        evidence = List.copyOf(evidence);
        if (id.isBlank() || role.isBlank() || ownership.isBlank()) {
            throw new IllegalArgumentException("Processor ID, role, and ownership must not be blank");
        }
        validateOptionalText(instructionSet, "Instruction set");
        validateOptionalText(ghidraLanguageId, "Ghidra language ID");
        validateOptionalText(compilerSpecId, "Compiler specification ID");
        if (kind.executesRecoverableInstructions() != instructionSet.isPresent()) {
            throw new IllegalArgumentException(
                "Instruction-bearing processor kinds require an ISA and other kinds forbid one");
        }
        if (compilerSpecId.isPresent() && ghidraLanguageId.isEmpty()) {
            throw new IllegalArgumentException("A compiler specification requires a Ghidra language");
        }
        if (addressSpaces.stream().anyMatch(String::isBlank)) {
            throw new IllegalArgumentException("Address-space IDs must not be blank");
        }
    }

    private static void validateOptionalText(Optional<String> value, String label) {
        if (value.filter(String::isBlank).isPresent()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
    }
}
