package io.github.rezabakhshi.embedra.targets.rp.pio;

import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Discovered and decoded PIO program extracted from Raspberry Pi firmware, including
 * origin, length, wrap configuration, side-set configuration, and decoded instruction list.
 */
public record RpPioProgram(
        long address,
        OptionalLong structureAddress,
        int length,
        int origin,
        List<RpPioInstruction> instructions,
        RpPioConfig config,
        String name) {

    public RpPioProgram {
        Objects.requireNonNull(structureAddress, "structureAddress must not be null");
        Objects.requireNonNull(config, "config must not be null");
        Objects.requireNonNull(name, "name must not be null");
        if (length <= 0 || length > 32) {
            throw new IllegalArgumentException("PIO program length must be between 1 and 32: " + length);
        }
        if (origin < -1 || origin > 31) {
            throw new IllegalArgumentException("PIO origin must be between -1 (relocatable) and 31: " + origin);
        }
        instructions = List.copyOf(Objects.requireNonNull(instructions, "instructions must not be null"));
        if (instructions.size() != length) {
            throw new IllegalArgumentException(
                    "Instruction count " + instructions.size() + " does not match length " + length);
        }
    }

    public boolean isRelocatable() {
        return origin == -1;
    }

    public long endAddress() {
        return address + (length * 2L);
    }
}
