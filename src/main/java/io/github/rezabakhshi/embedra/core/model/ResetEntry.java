package io.github.rezabakhshi.embedra.core.model;

import java.util.List;
import java.util.Objects;

/** Reset or entry candidate for one execution unit. */
public record ResetEntry(
        String name,
        String addressSpace,
        long address,
        Confidence confidence,
        List<Evidence> evidence) {
    public ResetEntry {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(addressSpace, "addressSpace");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
        if (name.isBlank() || addressSpace.isBlank()) {
            throw new IllegalArgumentException("Reset-entry name and address space must not be blank");
        }
        if (address < 0) {
            throw new IllegalArgumentException("Reset-entry address must be non-negative");
        }
    }
}
