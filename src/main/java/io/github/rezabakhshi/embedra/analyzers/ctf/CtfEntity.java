package io.github.rezabakhshi.embedra.analyzers.ctf;

import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable representation of a discovered firmware entity or CTF artifact (AN-002, AN-006).
 *
 * @param id unique identifier for the entity finding
 * @param category high-level entity classification
 * @param type specific entity type
 * @param severity security severity ranking
 * @param confidence detection confidence assessment
 * @param address memory address or offset where the entity was discovered
 * @param length byte length of the matched entity in memory
 * @param value raw text representation of the entity
 * @param explanation descriptive explanation of the finding
 * @param secret true if the entity represents sensitive or secret material (AN-008)
 * @param attributes optional structured metadata attributes
 */
public record CtfEntity(
        String id,
        CtfEntityCategory category,
        CtfEntityType type,
        CtfSeverity severity,
        StringConfidence confidence,
        long address,
        int length,
        String value,
        String explanation,
        boolean secret,
        Map<String, String> attributes) {

    public CtfEntity {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(severity, "severity must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        if (address < 0) {
            throw new IllegalArgumentException("Address must be non-negative: " + address);
        }
        if (length < 0) {
            throw new IllegalArgumentException("Length must be non-negative: " + length);
        }
        Objects.requireNonNull(value, "value must not be null");
        Objects.requireNonNull(explanation, "explanation must not be null");
        attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(Map.copyOf(attributes));
    }

    public CtfEntity(
            String id,
            CtfEntityCategory category,
            CtfEntityType type,
            CtfSeverity severity,
            StringConfidence confidence,
            long address,
            int length,
            String value,
            String explanation,
            boolean secret) {
        this(id, category, type, severity, confidence, address, length, value, explanation, secret, Map.of());
    }

    public boolean isSecret() {
        return secret;
    }

    /**
     * Returns a redacted representation of the value if this entity is marked secret (AN-008).
     */
    public String maskedValue() {
        if (!secret) {
            return value;
        }
        if (value.startsWith("flag{") && value.endsWith("}")) {
            return "flag{***REDACTED***}";
        }
        if (value.startsWith("CTF{") && value.endsWith("}")) {
            return "CTF{***REDACTED***}";
        }
        if (value.startsWith("AKIA") && value.length() == 20) {
            return "AKIA" + "*".repeat(16);
        }
        if (value.startsWith("ghp_") || value.startsWith("gho_") || value.startsWith("ghu_")) {
            return value.substring(0, 4) + "*".repeat(Math.max(4, value.length() - 4));
        }
        if (value.startsWith("xoxb-") || value.startsWith("xoxp-")) {
            return value.substring(0, 5) + "*".repeat(Math.max(5, value.length() - 5));
        }
        if (value.startsWith("eyJ") && value.contains(".")) {
            int firstDot = value.indexOf('.');
            return value.substring(0, firstDot) + ".***REDACTED***";
        }
        if (value.length() <= 8) {
            return "***REDACTED***";
        }
        return value.substring(0, 3) + "***REDACTED***" + value.substring(value.length() - 2);
    }

    @Override
    public String toString() {
        return "CtfEntity["
                + "id='" + id + '\''
                + ", category=" + category
                + ", type=" + type
                + ", severity=" + severity
                + ", confidence=" + confidence
                + ", address=0x" + Long.toHexString(address)
                + ", length=" + length
                + ", value='" + maskedValue() + '\''
                + ", secret=" + secret
                + ']';
    }
}
