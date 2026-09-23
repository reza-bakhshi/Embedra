package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.Objects;

/** One resolved crypto-related ROM or library call site. */
public record EspCryptoCallFact(
        long callAddress,
        long targetAddress,
        String targetName,
        String provenance) {
    public EspCryptoCallFact {
        if (callAddress < 0 || targetAddress < 0) {
            throw new IllegalArgumentException("Crypto call addresses must be non-negative");
        }
        requireText(targetName, "targetName");
        requireText(provenance, "provenance");
    }

    private static void requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
