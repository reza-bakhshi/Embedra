package io.github.rezabakhshi.embedra.targets.stm8.vector;

import java.util.Objects;

/**
 * Immutable record representing one parsed interrupt vector table entry on STM8.
 */
public record Stm8VectorEntry(
        Stm8VectorSlot slot,
        long vectorAddress,
        int opcode,
        long targetAddress,
        boolean validOpcode,
        boolean validTarget,
        String handlerLabel,
        String description,
        boolean isStub) {

    public Stm8VectorEntry {
        Objects.requireNonNull(slot, "slot must not be null");
        Objects.requireNonNull(handlerLabel, "handlerLabel must not be null");
        Objects.requireNonNull(description, "description must not be null");
    }

    public boolean isValid() {
        return validOpcode && validTarget;
    }
}
