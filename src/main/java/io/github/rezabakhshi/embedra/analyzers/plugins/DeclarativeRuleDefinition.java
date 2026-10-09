package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import java.util.Objects;

/**
 * Immutable definition of a declarative scanner pattern rule.
 *
 * @param ruleId unique rule identifier within the plugin
 * @param description human-readable explanation
 * @param matcherType matcher kind (REGEX, HEX_BYTES, EXACT_STRING, ENTROPY)
 * @param pattern pattern string, hex string, or empty for entropy
 * @param severity severity level
 * @param confidence confidence tier
 * @param confidenceScore numeric score between 0.0 and 1.0
 * @param secret true if the match represents sensitive material
 * @param category finding category
 * @param subcategory optional subcategory
 * @param minEntropy optional minimum entropy threshold (0.0 to 8.0)
 * @param maxEntropy optional maximum entropy threshold (0.0 to 8.0)
 */
public record DeclarativeRuleDefinition(
        String ruleId,
        String description,
        DeclarativeMatcherType matcherType,
        String pattern,
        FindingSeverity severity,
        FindingConfidence confidence,
        double confidenceScore,
        boolean secret,
        FindingCategory category,
        String subcategory,
        Double minEntropy,
        Double maxEntropy) {

    public DeclarativeRuleDefinition {
        Objects.requireNonNull(ruleId, "ruleId must not be null");
        Objects.requireNonNull(description, "description must not be null");
        Objects.requireNonNull(matcherType, "matcherType must not be null");
        pattern = pattern == null ? "" : pattern;
        Objects.requireNonNull(severity, "severity must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        if (confidenceScore < 0.0 || confidenceScore > 1.0) {
            throw new IllegalArgumentException("confidenceScore must be between 0.0 and 1.0: " + confidenceScore);
        }
        category = category == null ? FindingCategory.CUSTOM_PLUGIN : category;
        subcategory = (subcategory == null || subcategory.isBlank()) ? ruleId : subcategory;
        if (minEntropy != null && (minEntropy < 0.0 || minEntropy > 8.0)) {
            throw new IllegalArgumentException("minEntropy must be between 0.0 and 8.0: " + minEntropy);
        }
        if (maxEntropy != null && (maxEntropy < 0.0 || maxEntropy > 8.0)) {
            throw new IllegalArgumentException("maxEntropy must be between 0.0 and 8.0: " + maxEntropy);
        }
    }
}
