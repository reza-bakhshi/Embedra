package io.github.rezabakhshi.embedra.analyzers.findings;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Engine managing user suppression rules and evaluating findings for suppression (AN-006).
 */
public final class SuppressionEngine {

    private static final Pattern RULE_JSON_PATTERN = Pattern.compile(
            "\\{\\s*\"ruleId\":\\s*\"([^\"]+)\",\\s*\"matchType\":\\s*\"([^\"]+)\",\\s*"
                    + "\"pattern\":\\s*\"([^\"]+)\",\\s*\"reason\":\\s*\"([^\"]+)\",\\s*"
                    + "\"createdAt\":\\s*\"([^\"]+)\"\\s*\\}");

    private final List<SuppressionRule> rules;

    public SuppressionEngine() {
        this(List.of());
    }

    public SuppressionEngine(List<SuppressionRule> initialRules) {
        Objects.requireNonNull(initialRules, "initialRules must not be null");
        this.rules = new ArrayList<>(initialRules);
    }

    public synchronized List<SuppressionRule> rules() {
        return Collections.unmodifiableList(new ArrayList<>(rules));
    }

    public synchronized List<SuppressionRule> getRules() {
        return rules();
    }

    public synchronized void addRule(SuppressionRule rule) {
        Objects.requireNonNull(rule, "rule must not be null");
        rules.removeIf(r -> r.ruleId().equalsIgnoreCase(rule.ruleId()));
        rules.add(rule);
    }

    public synchronized boolean removeRule(String ruleId) {
        Objects.requireNonNull(ruleId, "ruleId must not be null");
        return rules.removeIf(r -> r.ruleId().equalsIgnoreCase(ruleId));
    }

    public synchronized void clearRules() {
        rules.clear();
    }

    /**
     * Evaluates a finding against all active suppression rules.
     *
     * @param finding finding to evaluate
     * @return updated finding with suppression status
     */
    public synchronized UnifiedFinding evaluate(UnifiedFinding finding) {
        Objects.requireNonNull(finding, "finding must not be null");
        for (SuppressionRule rule : rules) {
            if (rule.matches(finding)) {
                return finding.withSuppressed(true, rule.reason());
            }
        }
        return finding.withSuppressed(false, null);
    }

    public synchronized boolean isSuppressed(UnifiedFinding finding) {
        return evaluate(finding).suppressed();
    }

    public synchronized String getSuppressionReason(UnifiedFinding finding) {
        return evaluate(finding).suppressionReason();
    }

    /**
     * Applies suppression evaluation across a list of findings.
     */
    public synchronized List<UnifiedFinding> applySuppression(List<UnifiedFinding> findings) {
        Objects.requireNonNull(findings, "findings must not be null");
        List<UnifiedFinding> results = new ArrayList<>(findings.size());
        for (UnifiedFinding f : findings) {
            results.add(evaluate(f));
        }
        return Collections.unmodifiableList(results);
    }

    public synchronized List<UnifiedFinding> evaluate(List<UnifiedFinding> findings) {
        return applySuppression(findings);
    }

    /**
     * Serializes suppression rules to JSON.
     */
    public synchronized String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        for (int i = 0; i < rules.size(); i++) {
            SuppressionRule r = rules.get(i);
            sb.append("  {\n");
            sb.append("    \"ruleId\": \"").append(escape(r.ruleId())).append("\",\n");
            sb.append("    \"matchType\": \"").append(r.matchType().name()).append("\",\n");
            sb.append("    \"pattern\": \"").append(escape(r.pattern())).append("\",\n");
            sb.append("    \"reason\": \"").append(escape(r.reason())).append("\",\n");
            sb.append("    \"createdAt\": \"").append(escape(r.createdAt())).append("\"\n");
            sb.append("  }").append(i < rules.size() - 1 ? "," : "").append("\n");
        }
        sb.append("]\n");
        return sb.toString();
    }

    /**
     * Deserializes suppression rules from JSON.
     */
    public static SuppressionEngine fromJson(String json) {
        if (json == null || json.isBlank()) {
            return new SuppressionEngine();
        }
        List<SuppressionRule> parsed = new ArrayList<>();
        Matcher m = RULE_JSON_PATTERN.matcher(json);
        while (m.find()) {
            String ruleId = unescape(m.group(1));
            SuppressionRule.MatchType type = SuppressionRule.MatchType.valueOf(m.group(2));
            String pattern = unescape(m.group(3));
            String reason = unescape(m.group(4));
            String createdAt = unescape(m.group(5));
            parsed.add(new SuppressionRule(ruleId, type, pattern, reason, createdAt));
        }
        return new SuppressionEngine(parsed);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static String unescape(String s) {
        return s.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
