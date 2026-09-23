package io.github.rezabakhshi.embedra.ghidra.esp;

import java.util.Objects;

/** One removable memory block created by pack enrichment. */
public record EspCreatedBlock(String name, long start, long length) {
    public EspCreatedBlock {
        Objects.requireNonNull(name, "name");
        if (name.isBlank() || start < 0 || length <= 0
            || start + length > 0x1_0000_0000L) {
            throw new IllegalArgumentException("Created block is invalid");
        }
    }
}
