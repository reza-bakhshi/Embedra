package io.github.rezabakhshi.embedra.analyzers.crypto.dataflow;

import java.util.Objects;

/**
 * Destination or use-site for cryptographic data flow or taint propagation (AN-010, AN-013).
 */
public record TaintSink(
        String id,
        long address,
        TaintSinkKind kind,
        String targetFunctionOrRegister) {

    /** Categorization of cryptographic taint sinks. */
    public enum TaintSinkKind {
        CRYPTO_API_CALL,
        HARDWARE_MMIO_WRITE,
        PERIPHERAL_TRIGGER,
        STORAGE_WRITE,
        NETWORK_TRANSMIT
    }

    public TaintSink {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(kind, "kind must not be null");
        Objects.requireNonNull(targetFunctionOrRegister, "targetFunctionOrRegister must not be null");
    }
}
