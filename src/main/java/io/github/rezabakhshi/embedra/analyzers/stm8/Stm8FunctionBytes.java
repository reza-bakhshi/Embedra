package io.github.rezabakhshi.embedra.analyzers.stm8;

import java.util.Objects;

/** One bounded candidate function byte region supplied to the STM8 signature matcher. */
public record Stm8FunctionBytes(long address, byte[] bytes) {
    public Stm8FunctionBytes {
        if (address < 0) {
            throw new IllegalArgumentException("Function address must be non-negative");
        }
        bytes = Objects.requireNonNull(bytes, "bytes").clone();
        if (bytes.length == 0) {
            throw new IllegalArgumentException("Function bytes must not be empty");
        }
    }

    @Override
    public byte[] bytes() {
        return bytes.clone();
    }
}
