package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable pack of cryptographic library signatures with integrity validation (AN-011, CORE-013).
 */
public record CryptoSignaturePack(
        String schemaId,
        String packId,
        String version,
        String description,
        List<CryptoLibrarySignature> signatures,
        String integrityDigest) {

    public static final String SCHEMA_ID = "urn:embedra:schema:crypto-signature-pack:1";

    public CryptoSignaturePack {
        Objects.requireNonNull(schemaId, "schemaId must not be null");
        Objects.requireNonNull(packId, "packId must not be null");
        Objects.requireNonNull(version, "version must not be null");
        Objects.requireNonNull(description, "description must not be null");
        Objects.requireNonNull(signatures, "signatures must not be null");
        Objects.requireNonNull(integrityDigest, "integrityDigest must not be null");

        if (!SCHEMA_ID.equals(schemaId)) {
            throw new IllegalArgumentException("Unsupported schemaId: " + schemaId);
        }
        if (signatures.isEmpty()) {
            throw new IllegalArgumentException("signatures must not be empty");
        }
        signatures = Collections.unmodifiableList(List.copyOf(signatures));
    }
}
