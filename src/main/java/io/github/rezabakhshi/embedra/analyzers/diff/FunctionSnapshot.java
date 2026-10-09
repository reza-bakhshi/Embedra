package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Immutable snapshot of a disassembled firmware function for workspace diffing (T062).
 *
 * @param name function name or label
 * @param address entry point memory address
 * @param length byte length of the function body
 * @param bodyHash cryptographic or instruction body hash
 * @param signature parameter and return type signature string
 */
public record FunctionSnapshot(
        String name,
        long address,
        long length,
        String bodyHash,
        String signature) {

    public FunctionSnapshot {
        Objects.requireNonNull(name, "name must not be null");
        bodyHash = bodyHash == null ? "" : bodyHash;
        signature = signature == null ? "" : signature;
        if (address < 0) {
            throw new IllegalArgumentException("Address must be non-negative: " + address);
        }
        if (length < 0) {
            throw new IllegalArgumentException("Length must be non-negative: " + length);
        }
    }
}
