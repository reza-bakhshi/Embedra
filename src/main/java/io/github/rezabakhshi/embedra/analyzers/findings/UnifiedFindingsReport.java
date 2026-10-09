package io.github.rezabakhshi.embedra.analyzers.findings;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Aggregated report of unified findings with sorting, filtering, and multi-format export (AN-006, AN-008).
 */
public final class UnifiedFindingsReport {

    private static final Pattern SENSITIVE_PATTERN = Pattern.compile(
            "(?i)(password|secret|token|api[_-]?key|credential|private[_-]?key|auth)"
                    + "([:=]|\\s+is\\s+|\\s+as\\s+)?\\s*([A-Za-z0-9+/=_-]{4,})");

    private static final Comparator<UnifiedFinding> RANK_COMPARATOR = (f1, f2) -> {
        int c = Integer.compare(f2.severity().rank(), f1.severity().rank());
        if (c != 0) {
            return c;
        }
        c = Integer.compare(f2.confidence().rank(), f1.confidence().rank());
        if (c != 0) {
            return c;
        }
        c = Double.compare(f2.confidenceScore(), f1.confidenceScore());
        if (c != 0) {
            return c;
        }
        return Long.compare(f1.address(), f2.address());
    };

    private final List<UnifiedFinding> findings;

    private final List<UnifiedFinding> rankedFindings;

    public UnifiedFindingsReport(List<UnifiedFinding> findings) {
        Objects.requireNonNull(findings, "findings must not be null");
        this.findings = List.copyOf(findings);
        List<UnifiedFinding> sorted = new ArrayList<>(this.findings);
        sorted.sort(RANK_COMPARATOR);
        this.rankedFindings = Collections.unmodifiableList(sorted);
    }

    public static UnifiedFindingsReport of(String programName, String platform, List<UnifiedFinding> findings) {
        return new UnifiedFindingsReport(findings);
    }

    public List<UnifiedFinding> findings() {
        return findings;
    }

    public List<UnifiedFinding> rankedFindings() {
        return rankedFindings;
    }

    public List<UnifiedFinding> activeFindings() {
        return findings.stream().filter(f -> !f.suppressed()).toList();
    }

    public List<UnifiedFinding> suppressedFindings() {
        return findings.stream().filter(UnifiedFinding::suppressed).toList();
    }

    public int totalCount() {
        return findings.size();
    }

    public int activeCount() {
        return (int) findings.stream().filter(f -> !f.suppressed()).count();
    }

    public int suppressedCount() {
        return (int) findings.stream().filter(UnifiedFinding::suppressed).count();
    }

    /**
     * Aggregates active findings count grouped by {@link FindingCategory}.
     */
    public Map<FindingCategory, Integer> countByCategory() {
        Map<FindingCategory, Integer> map = new EnumMap<>(FindingCategory.class);
        for (FindingCategory cat : FindingCategory.values()) {
            map.put(cat, 0);
        }
        for (UnifiedFinding f : findings) {
            if (!f.suppressed()) {
                map.put(f.category(), map.get(f.category()) + 1);
            }
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Aggregates active findings count grouped by {@link FindingSeverity}.
     */
    public Map<FindingSeverity, Integer> countBySeverity() {
        Map<FindingSeverity, Integer> map = new EnumMap<>(FindingSeverity.class);
        for (FindingSeverity sev : FindingSeverity.values()) {
            map.put(sev, 0);
        }
        for (UnifiedFinding f : findings) {
            if (!f.suppressed()) {
                map.put(f.severity(), map.get(f.severity()) + 1);
            }
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Aggregates active findings count grouped by {@link FindingConfidence}.
     */
    public Map<FindingConfidence, Integer> countByConfidence() {
        Map<FindingConfidence, Integer> map = new EnumMap<>(FindingConfidence.class);
        for (FindingConfidence conf : FindingConfidence.values()) {
            map.put(conf, 0);
        }
        for (UnifiedFinding f : findings) {
            if (!f.suppressed()) {
                map.put(f.confidence(), map.get(f.confidence()) + 1);
            }
        }
        return Collections.unmodifiableMap(map);
    }

    public String toJson(boolean redactSecrets) {
        return toJson(redactSecrets, true);
    }

    /**
     * Serializes findings to JSON with secret masking and suppression filtering (AN-008).
     */
    public String toJson(boolean redactSecrets, boolean includeSuppressed) {
        List<UnifiedFinding> list = includeSuppressed ? rankedFindings
                : rankedFindings.stream().filter(f -> !f.suppressed()).toList();

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"totalFindings\": ").append(findings.size()).append(",\n");
        sb.append("  \"activeCount\": ").append(activeCount()).append(",\n");
        sb.append("  \"suppressedCount\": ").append(suppressedCount()).append(",\n");
        sb.append("  \"redacted\": ").append(redactSecrets).append(",\n");
        sb.append("  \"findings\": [\n");

        for (int i = 0; i < list.size(); i++) {
            UnifiedFinding f = list.get(i);
            String target = f.maskedTarget(redactSecrets);
            String expl = redactSecrets ? maskSensitive(f.explanation()) : f.explanation();

            sb.append("    {\n");
            sb.append("      \"id\": \"").append(escapeJson(f.id())).append("\",\n");
            sb.append("      \"category\": \"").append(f.category().name()).append("\",\n");
            sb.append("      \"subcategory\": \"").append(escapeJson(f.subcategory())).append("\",\n");
            sb.append("      \"severity\": \"").append(f.severity().name()).append("\",\n");
            sb.append("      \"confidence\": \"").append(f.confidence().name()).append("\",\n");
            sb.append("      \"confidenceScore\": ").append(String.format("%.3f", f.confidenceScore())).append(",\n");
            sb.append("      \"platform\": \"").append(escapeJson(f.platform())).append("\",\n");
            sb.append("      \"address\": ").append(f.address()).append(",\n");
            sb.append("      \"length\": ").append(f.length()).append(",\n");
            sb.append("      \"target\": \"").append(escapeJson(target)).append("\",\n");
            sb.append("      \"explanation\": \"").append(escapeJson(expl)).append("\",\n");
            sb.append("      \"secret\": ").append(f.secret()).append(",\n");
            sb.append("      \"suppressed\": ").append(f.suppressed()).append(",\n");
            String reason = f.suppressionReason() != null ? f.suppressionReason() : "";
            sb.append("      \"suppressionReason\": \"").append(escapeJson(reason)).append("\"\n");
            sb.append("    }").append(i < list.size() - 1 ? "," : "").append("\n");
        }

        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    public String toMarkdown(boolean redactSecrets) {
        return toMarkdown(redactSecrets, true);
    }

    /**
     * Serializes findings to Markdown summary and table.
     */
    public String toMarkdown(boolean redactSecrets, boolean includeSuppressed) {
        List<UnifiedFinding> list = includeSuppressed ? rankedFindings
                : rankedFindings.stream().filter(f -> !f.suppressed()).toList();

        StringBuilder sb = new StringBuilder();
        sb.append("# Embedra Unified Security Findings Report (AN-006, AN-008)\n\n");
        sb.append("**Active Findings**: ").append(activeCount())
                .append(" | **Suppressed Findings**: ").append(suppressedCount())
                .append(" | **Total**: ").append(findings.size()).append("\n\n");

        sb.append("| # | Severity | Confidence | Category | Subcategory | Address | Target | Platform | "
                + "Explanation |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

        for (int i = 0; i < list.size(); i++) {
            UnifiedFinding f = list.get(i);
            String target = f.maskedTarget(redactSecrets);
            String expl = redactSecrets ? maskSensitive(f.explanation()) : f.explanation();
            String statusPrefix = f.suppressed() ? "~~" : "";
            String statusSuffix = f.suppressed() ? "~~ (SUPPRESSED)" : "";

            sb.append("| ").append(i + 1)
                    .append(" | ").append(f.severity().displayName())
                    .append(" | ").append(f.confidence().displayName())
                    .append(" | ").append(f.category().displayName())
                    .append(" | ").append(f.subcategory())
                    .append(" | 0x").append(Long.toHexString(f.address()))
                    .append(" | ").append(statusPrefix).append("`").append(target.replace("`", "'")).append("`")
                    .append(statusSuffix)
                    .append(" | ").append(f.platform())
                    .append(" | ").append(expl.replace("|", "\\|"))
                    .append(" |\n");
        }

        return sb.toString();
    }

    public String toSarif(boolean redactSecrets) {
        return toSarif(redactSecrets, true);
    }

    /**
     * Serializes findings to SARIF 2.1.0 format.
     */
    public String toSarif(boolean redactSecrets, boolean includeSuppressed) {
        List<UnifiedFinding> list = includeSuppressed ? rankedFindings
                : rankedFindings.stream().filter(f -> !f.suppressed()).toList();

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
        sb.append("  \"version\": \"2.1.0\",\n");
        sb.append("  \"runs\": [\n");
        sb.append("    {\n");
        sb.append("      \"tool\": {\n");
        sb.append("        \"driver\": {\n");
        sb.append("          \"name\": \"Embedra Static Analysis\",\n");
        sb.append("          \"version\": \"1.0.0\"\n");
        sb.append("        }\n");
        sb.append("      },\n");
        sb.append("      \"results\": [\n");

        for (int i = 0; i < list.size(); i++) {
            UnifiedFinding f = list.get(i);
            String expl = redactSecrets ? maskSensitive(f.explanation()) : f.explanation();
            String level = switch (f.severity()) {
                case CRITICAL, HIGH -> "error";
                case MEDIUM -> "warning";
                case LOW, INFO -> "note";
            };

            sb.append("        {\n");
            sb.append("          \"ruleId\": \"EMBEDRA-").append(f.category().name()).append("-")
                    .append(f.subcategory()).append("\",\n");
            sb.append("          \"level\": \"").append(level).append("\",\n");
            sb.append("          \"message\": {\n");
            sb.append("            \"text\": \"").append(escapeJson(expl)).append("\"\n");
            sb.append("          },\n");
            if (f.suppressed()) {
                sb.append("          \"suppressions\": [\n");
                sb.append("            {\n");
                sb.append("              \"kind\": \"external\",\n");
                String r = f.suppressionReason() != null ? f.suppressionReason() : "User suppression rule";
                sb.append("              \"justification\": \"").append(escapeJson(r)).append("\"\n");
                sb.append("            }\n");
                sb.append("          ],\n");
            }
            sb.append("          \"locations\": [\n");
            sb.append("            {\n");
            sb.append("              \"physicalLocation\": {\n");
            sb.append("                \"address\": {\n");
            sb.append("                  \"absoluteAddress\": ").append(f.address()).append("\n");
            sb.append("                }\n");
            sb.append("              }\n");
            sb.append("            }\n");
            sb.append("          ]\n");
            sb.append("        }").append(i < list.size() - 1 ? "," : "").append("\n");
        }

        sb.append("      ]\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String maskSensitive(String input) {
        if (input == null) {
            return "";
        }
        return SENSITIVE_PATTERN.matcher(input).replaceAll("$1$2 [REDACTED_SECRET]");
    }

    private static String escapeJson(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
