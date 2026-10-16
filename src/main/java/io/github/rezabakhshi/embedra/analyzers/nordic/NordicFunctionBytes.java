package io.github.rezabakhshi.embedra.analyzers.nordic;

import java.util.Objects;

/** One bounded candidate function byte region supplied to the Nordic signature matcher. */
public record NordicFunctionBytes(long address, byte[] bytes) {

    public NordicFunctionBytes {
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
