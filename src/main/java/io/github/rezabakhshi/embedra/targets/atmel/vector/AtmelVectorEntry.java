package io.github.rezabakhshi.embedra.targets.atmel.vector;

import java.util.Objects;

/**
 * Immutable parsed entry in an Atmel / Microchip interrupt vector table.
 */
public record AtmelVectorEntry(
        AtmelVectorSlot slot,
        long entryAddress,
        long targetAddress,
        long rawInstruction,
        AtmelVectorInstructionType instructionType,
        boolean isValid,
        boolean isStub,
        String canonicalLabel) {

    public AtmelVectorEntry {
        Objects.requireNonNull(slot, "slot must not be null");
        Objects.requireNonNull(instructionType, "instructionType must not be null");
        Objects.requireNonNull(canonicalLabel, "canonicalLabel must not be null");
    }

    public boolean isReset() {
        return slot.index() == 0 && instructionType != AtmelVectorInstructionType.INITIAL_SP
            || slot.index() == 1 && instructionType == AtmelVectorInstructionType.THUMB_VECTOR;
    }
}
