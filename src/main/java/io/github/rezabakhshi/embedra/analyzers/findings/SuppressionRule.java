package io.github.rezabakhshi.embedra.analyzers.findings;

import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Immutable rule defining criteria to suppress false-positive or expected findings (AN-006).
 *
 * @param ruleId unique identifier for the suppression rule
 * @param matchType criteria type used for matching
 * @param pattern value or regular expression to match against
 * @param reason justification for suppressing matching findings
 * @param createdAt timestamp when the rule was created
 */
public record SuppressionRule(
        String ruleId,
        MatchType matchType,
        String pattern,
        String reason,
        String createdAt) {

    public enum MatchType {
        FINDING_ID,
        EXACT_ADDRESS,
        CATEGORY,
        TARGET_PATTERN,
        EXPLANATION_PATTERN
    }

    public SuppressionRule {
        Objects.requireNonNull(ruleId, "ruleId must not be null");
        Objects.requireNonNull(matchType, "matchType must not be null");
        Objects.requireNonNull(pattern, "pattern must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        createdAt = createdAt == null ? Instant.now().toString() : createdAt;
    }

    public static SuppressionRule of(String ruleId, MatchType matchType, String pattern, String reason) {
        return new SuppressionRule(ruleId, matchType, pattern, reason, Instant.now().toString());
    }

    /**
     * Checks whether a unified finding matches this suppression rule.
     *
     * @param finding candidate finding to evaluate
     * @return true if finding matches and should be suppressed
     */
    public boolean matches(UnifiedFinding finding) {
        Objects.requireNonNull(finding, "finding must not be null");
        return switch (matchType) {
            case FINDING_ID -> finding.id().equalsIgnoreCase(pattern.trim());
            case EXACT_ADDRESS -> {
                try {
                    long targetAddr = parseAddress(pattern);
                    yield finding.address() == targetAddr;
                } catch (Exception e) {
                    yield false;
                }
            }
            case CATEGORY -> finding.category().name().equalsIgnoreCase(pattern.trim())
                    || (finding.subcategory() != null && finding.subcategory().equalsIgnoreCase(pattern.trim()));
            case TARGET_PATTERN -> {
                try {
                    yield Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(finding.target()).find();
                } catch (Exception e) {
                    yield finding.target().contains(pattern);
                }
            }
            case EXPLANATION_PATTERN -> {
                try {
                    yield Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(finding.explanation()).find();
                } catch (Exception e) {
                    yield finding.explanation().contains(pattern);
                }
            }
        };
    }

    private static long parseAddress(String raw) {
        String clean = raw.trim().toLowerCase(java.util.Locale.ROOT);
        if (clean.startsWith("0x")) {
            return Long.parseUnsignedLong(clean.substring(2), 16);
        }
        return Long.parseUnsignedLong(clean);
    }
}
