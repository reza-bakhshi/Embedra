package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.Objects;

/** Bounded function bytes used by an exact, version-indexed signature detector. */
public final class EspFunctionFact {
    private final long address;

    private final byte[] bytes;

    public EspFunctionFact(long address, byte[] bytes) {
        if (address < 0) {
            throw new IllegalArgumentException("Function address must not be negative");
        }
        this.address = address;
        this.bytes = Objects.requireNonNull(bytes, "bytes").clone();
        if (this.bytes.length == 0) {
            throw new IllegalArgumentException("Function bytes must not be empty");
        }
    }

    public long address() {
        return address;
    }

    public byte[] bytes() {
        return bytes.clone();
    }
}
