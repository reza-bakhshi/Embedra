package io.github.rezabakhshi.embedra.analyzers.crypto;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable finding produced by the layered cryptographic analysis pipeline (AN-003, AN-008, AN-010).
 *
 * @param id unique identifier for the finding
 * @param address memory address or offset where the finding was identified
 * @param length byte length of the matched region or structure
 * @param category high-level cryptographic or related classification
 * @param algorithm specific detected algorithm or primitive
 * @param confidence confidence level assessment
 * @param evidenceLayers layers of evidence that contributed to this finding
 * @param explanation human-readable explanation of why this was identified
 * @param rawValue raw value representation (e.g. hex encoded bytes)
 * @param secret true if the value represents sensitive or secret material (e.g. candidate keys)
 * @param attributes additional structured metadata
 */
public record CryptoFinding(
        String id,
        long address,
        int length,
        CryptoCategory category,
        CryptoAlgorithm algorithm,
        CryptoConfidence confidence,
        Set<CryptoEvidenceLayer> evidenceLayers,
        String explanation,
        String rawValue,
        boolean secret,
        Map<String, String> attributes) {

    public CryptoFinding {
        Objects.requireNonNull(id, "id must not be null");
        if (address < 0) {
            throw new IllegalArgumentException("Address must be non-negative: " + address);
        }
        if (length < 0) {
            throw new IllegalArgumentException("Length must be non-negative: " + length);
        }
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        Objects.requireNonNull(evidenceLayers, "evidenceLayers must not be null");
        Objects.requireNonNull(explanation, "explanation must not be null");
        Objects.requireNonNull(rawValue, "rawValue must not be null");
        evidenceLayers = Collections.unmodifiableSet(Set.copyOf(evidenceLayers));
        attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(Map.copyOf(attributes));
    }

    public CryptoFinding(
            String id,
            long address,
            int length,
            CryptoCategory category,
            CryptoAlgorithm algorithm,
            CryptoConfidence confidence,
            Set<CryptoEvidenceLayer> evidenceLayers,
            String explanation,
            String rawValue,
            boolean secret) {
        this(id, address, length, category, algorithm, confidence,
                evidenceLayers, explanation, rawValue, secret, Map.of());
    }

    public CryptoFinding(
            String id,
            long address,
            int length,
            CryptoCategory category,
            CryptoAlgorithm algorithm,
            CryptoConfidence confidence,
            CryptoEvidenceLayer singleLayer,
            String explanation,
            String rawValue,
            boolean secret) {
        this(id, address, length, category, algorithm, confidence,
                Set.of(singleLayer), explanation, rawValue, secret, Map.of());
    }

    public boolean isSecret() {
        return secret;
    }

    /**
     * In accordance with AN-003, returns true if and only if this finding represents an encryption cipher.
     * Checksums/CRCs, encodings, compression, and entropy anomalies will always return false.
     */
    public boolean isEncryption() {
        return category.isEncryption();
    }

    /**
     * Returns a redacted/masked representation if this finding represents sensitive secret material (AN-008).
     */
    public String maskedValue() {
        if (!secret) {
            return rawValue;
        }
        if (rawValue.isEmpty()) {
            return "***REDACTED***";
        }
        if (rawValue.length() <= 8) {
            return "***REDACTED***";
        }
        // For hex keys or strings: reveal first 4 characters and mask remainder with asterisks
        return rawValue.substring(0, 4) + "*".repeat(Math.max(4, rawValue.length() - 4));
    }
}
