package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.Objects;
import java.util.OptionalLong;

/** One static MMIO fact; a missing value means the stored value was not resolved. */
public record EspMemoryAccessFact(
        long instructionAddress,
        long targetAddress,
        EspMemoryAccessKind kind,
        OptionalLong resolvedValue) {
    public EspMemoryAccessFact {
        if (instructionAddress < 0 || targetAddress < 0) {
            throw new IllegalArgumentException("Memory access addresses must be non-negative");
        }
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(resolvedValue, "resolvedValue");
    }
}
