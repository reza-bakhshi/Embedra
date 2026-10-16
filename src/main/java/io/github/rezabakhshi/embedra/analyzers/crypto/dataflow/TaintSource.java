package io.github.rezabakhshi.embedra.analyzers.crypto.dataflow;

import java.util.Objects;

/**
 * Origin point for cryptographic data flow or taint propagation (AN-010, AN-013).
 */
public record TaintSource(
        String id,
        long address,
        TaintSourceKind kind,
        String label) {

    /** Categorization of cryptographic taint sources. */
    public enum TaintSourceKind {
        CONSTANT_TABLE,
        HARDWARE_MMIO_READ,
        EFUSE_OTP_READ,
        NVS_KEY_STORE,
        HIGH_ENTROPY_KEY_CANDIDATE,
        FUNCTION_PARAMETER
    }

    public TaintSource {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(kind, "kind must not be null");
        Objects.requireNonNull(label, "label must not be null");
    }
}
