package io.github.rezabakhshi.embedra.analyzers.atmel;

import java.util.Objects;

/** One bounded candidate function byte region supplied to the Atmel/Microchip signature matcher. */
public record AtmelFunctionBytes(long address, byte[] bytes) {

    public AtmelFunctionBytes {
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
