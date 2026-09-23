package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** A decoded program string with both target and source location. */
public record EspStringFact(long address, String value, SourceRange sourceRange) {
    public EspStringFact {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(sourceRange, "sourceRange");
        if (address < 0 || value.isEmpty()) {
            throw new IllegalArgumentException("ESP string facts require an address and value");
        }
    }
}
