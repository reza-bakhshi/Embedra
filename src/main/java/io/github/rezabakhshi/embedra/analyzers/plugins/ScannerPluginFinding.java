package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFinding;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable finding produced by a local scanner plugin (AN-006, AN-008, AN-009).
 */
public record ScannerPluginFinding(
        String findingId,
        String pluginId,
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
        Map<String, String> attributes) {

    public ScannerPluginFinding {
        Objects.requireNonNull(findingId, "findingId must not be null");
        Objects.requireNonNull(pluginId, "pluginId must not be null");
        category = category == null ? FindingCategory.CUSTOM_PLUGIN : category;
        subcategory = subcategory == null ? "PLUGIN_MATCH" : subcategory;
        Objects.requireNonNull(severity, "severity must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        if (confidenceScore < 0.0 || confidenceScore > 1.0) {
            throw new IllegalArgumentException("confidenceScore must be between 0.0 and 1.0: " + confidenceScore);
        }
        platform = (platform == null || platform.isBlank()) ? "GENERIC" : platform;
        if (address < 0) {
            throw new IllegalArgumentException("address must be non-negative: " + address);
        }
        if (length < 0) {
            throw new IllegalArgumentException("length must be non-negative: " + length);
        }
        target = target == null ? "" : target;
        Objects.requireNonNull(explanation, "explanation must not be null");
        attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(Map.copyOf(attributes));
    }

    /**
     * Converts this plugin finding into a canonical {@link UnifiedFinding} (AN-006).
     */
    public UnifiedFinding toUnifiedFinding() {
        Map<String, String> attrs = new LinkedHashMap<>(attributes);
        attrs.put("pluginId", pluginId);
        return new UnifiedFinding(
                findingId,
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
                false,
                null,
                attrs
        );
    }

    /**
     * Returns the target value, masked with [REDACTED_SECRET] if secret and redaction requested (AN-008).
     */
    public String maskedTarget(boolean redactSecrets) {
        if (redactSecrets && secret) {
            return "[REDACTED_SECRET]";
        }
        return target;
    }
}
