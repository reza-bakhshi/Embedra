package io.github.rezabakhshi.embedra.analyzers.findings;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Canonical unified finding model consolidating outputs from all Embedra analyzers (AN-006, AN-008).
 *
 * @param id unique finding identifier
 * @param category top-level classification category
 * @param subcategory specific finding type or algorithm identity
 * @param severity triage severity level
 * @param confidence confidence tier assessment
 * @param confidenceScore normalized numeric confidence score between 0.0 and 1.0
 * @param platform target architecture or device platform
 * @param address program memory address where the finding was identified
 * @param length byte length of the matched element in memory
 * @param target primary matched string, command, endpoint URL, or comparison operand
 * @param explanation human-readable summary of the finding
 * @param secret true if the finding represents sensitive secret or credential material (AN-008)
 * @param suppressed true if this finding has been suppressed by an active suppression rule
 * @param suppressionReason explanation for suppression if suppressed
 * @param attributes structured metadata attributes
 */
public record UnifiedFinding(
        String id,
        FindingCategory category,
        String subcategory,
        FindingSeverity severity,
        FindingConfidence confidence,
        double confidenceScore,
        String platform,
        long address,
        int length,
        String target,
        String explanation,
        boolean secret,
        boolean suppressed,
        String suppressionReason,
        Map<String, String> attributes) {

    public UnifiedFinding {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(subcategory, "subcategory must not be null");
        Objects.requireNonNull(severity, "severity must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        platform = (platform == null || platform.isBlank()) ? "GENERIC" : platform;
        if (address < 0) {
            throw new IllegalArgumentException("Address must be non-negative: " + address);
        }
        if (length < 0) {
            throw new IllegalArgumentException("Length must be non-negative: " + length);
        }
        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(explanation, "explanation must not be null");
        attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(Map.copyOf(attributes));
    }

    /**
     * Returns a copy of this finding with updated suppression state.
     */
    public UnifiedFinding withSuppressed(boolean isSuppressed, String reason) {
        return new UnifiedFinding(
                id,
                category,
                subcategory,
                severity,
                confidence,
                confidenceScore,
                platform,
                address,
                length,
                target,
                explanation,
                secret,
                isSuppressed,
                reason,
                attributes);
    }

    /**
     * Returns the target value, masked with [REDACTED_SECRET] if secret and redaction requested (AN-008).
     *
     * @param redactSecrets whether secret parameters should be masked
     * @return redacted or raw target
     */
    public String maskedTarget(boolean redactSecrets) {
        if (redactSecrets && secret) {
            return "[REDACTED_SECRET]";
        }
        return target;
    }
}
