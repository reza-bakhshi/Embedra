package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.List;
import java.util.Objects;

/** Resolved call site and the constant pointer arguments proven at that site. */
public record EspCallFact(
        long callAddress, long callerAddress, long targetAddress, List<Long> arguments) {
    public EspCallFact {
        Objects.requireNonNull(arguments, "arguments");
        arguments = List.copyOf(arguments);
        if (callAddress < 0 || callerAddress < 0 || targetAddress < 0
            || arguments.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("Invalid ESP call fact");
        }
    }
}
