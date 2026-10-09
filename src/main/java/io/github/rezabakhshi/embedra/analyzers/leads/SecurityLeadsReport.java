package io.github.rezabakhshi.embedra.analyzers.leads;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Aggregated report of candidate security leads with heuristic ranking and structured export (AN-005, AN-008).
 */
public final class SecurityLeadsReport {

    private static final Pattern SENSITIVE_PATTERN = Pattern.compile(
            "(?i)(password|secret|token|api[_-]?key|credential|private[_-]?key|auth)"
                    + "([:=]|\\s+is\\s+|\\s+as\\s+)?\\s*([A-Za-z0-9+/=_-]{4,})");

    private static final Comparator<SecurityLead> RANK_COMPARATOR = Comparator
            .comparingDouble(SecurityLead::confidenceScore).reversed()
            .thenComparing((SecurityLead l) -> l.severity().rank(), Comparator.reverseOrder())
            .thenComparingLong(SecurityLead::address);

    private final List<SecurityLead> leads;

    private final List<SecurityLead> rankedLeads;

    public SecurityLeadsReport(List<SecurityLead> leads) {
        Objects.requireNonNull(leads, "leads must not be null");
        this.leads = List.copyOf(leads);
        List<SecurityLead> sorted = new ArrayList<>(this.leads);
        sorted.sort(RANK_COMPARATOR);
        this.rankedLeads = Collections.unmodifiableList(sorted);
    }

    public List<SecurityLead> leads() {
        return leads;
    }

    public List<SecurityLead> rankedLeads() {
        return rankedLeads;
    }

    public int totalCount() {
        return leads.size();
    }

    /**
     * Filters leads by category.
     */
    public List<SecurityLead> leadsByCategory(LeadCategory category) {
        Objects.requireNonNull(category, "category must not be null");
        return leads.stream()
                .filter(l -> l.category() == category)
                .toList();
    }

    /**
     * Filters leads by confidence tier.
     */
    public List<SecurityLead> leadsByConfidence(LeadConfidence confidence) {
        Objects.requireNonNull(confidence, "confidence must not be null");
        return leads.stream()
                .filter(l -> l.confidence() == confidence)
                .toList();
    }

    /**
     * Aggregates count of leads by category.
     */
    public Map<LeadCategory, Integer> countByCategory() {
        Map<LeadCategory, Integer> map = new EnumMap<>(LeadCategory.class);
        for (LeadCategory cat : LeadCategory.values()) {
            map.put(cat, 0);
        }
        for (SecurityLead lead : leads) {
            map.put(lead.category(), map.get(lead.category()) + 1);
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Aggregates count of leads by confidence tier.
     */
    public Map<LeadConfidence, Integer> countByConfidence() {
        Map<LeadConfidence, Integer> map = new EnumMap<>(LeadConfidence.class);
        for (LeadConfidence conf : LeadConfidence.values()) {
            map.put(conf, 0);
        }
        for (SecurityLead lead : leads) {
            map.put(lead.confidence(), map.get(lead.confidence()) + 1);
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Aggregates count of leads by severity.
     */
    public Map<LeadSeverity, Integer> countBySeverity() {
        Map<LeadSeverity, Integer> map = new EnumMap<>(LeadSeverity.class);
        for (LeadSeverity sev : LeadSeverity.values()) {
            map.put(sev, 0);
        }
        for (SecurityLead lead : leads) {
            map.put(lead.severity(), map.get(lead.severity()) + 1);
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Serializes ranked leads to JSON with secret masking support (AN-008).
     */
    public String toJson(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"totalLeads\": ").append(leads.size()).append(",\n");
        sb.append("  \"redacted\": ").append(redactSecrets).append(",\n");
        sb.append("  \"rankedLeads\": [\n");
        for (int i = 0; i < rankedLeads.size(); i++) {
            SecurityLead l = rankedLeads.get(i);
            String target = l.maskedTarget(redactSecrets);
            String desc = redactSecrets ? maskSensitive(l.description()) : l.description();
            sb.append("    {\n");
            sb.append("      \"id\": \"").append(escapeJson(l.id())).append("\",\n");
            sb.append("      \"category\": \"").append(l.category().name()).append("\",\n");
            sb.append("      \"confidence\": \"").append(l.confidence().name()).append("\",\n");
            sb.append("      \"confidenceScore\": ").append(String.format("%.3f", l.confidenceScore())).append(",\n");
            sb.append("      \"severity\": \"").append(l.severity().name()).append("\",\n");
            sb.append("      \"address\": ").append(l.address()).append(",\n");
            sb.append("      \"symbol\": \"").append(escapeJson(l.symbol() != null ? l.symbol() : "")).append("\",\n");
            sb.append("      \"target\": \"").append(escapeJson(target)).append("\",\n");
            sb.append("      \"description\": \"").append(escapeJson(desc)).append("\",\n");
            sb.append("      \"secret\": ").append(l.secret()).append(",\n");
            sb.append("      \"heuristicFactors\": [");
            for (int h = 0; h < l.heuristicFactors().size(); h++) {
                HeuristicFactor hf = l.heuristicFactors().get(h);
                sb.append("\"").append(escapeJson(hf.factorId())).append("\"");
                if (h < l.heuristicFactors().size() - 1) {
                    sb.append(", ");
                }
            }
            sb.append("]\n");
            sb.append("    }").append(i < rankedLeads.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Serializes ranked leads to Markdown table.
     */
    public String toMarkdown(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Candidate Security Leads (AN-005)\n\n");
        sb.append("> **Note**: These findings are ranked heuristic leads, not confirmed vulnerabilities.\n\n");
        sb.append("| Rank | Category | Confidence | Score | Severity | Address | Symbol | Target | Description |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for (int i = 0; i < rankedLeads.size(); i++) {
            SecurityLead l = rankedLeads.get(i);
            String target = l.maskedTarget(redactSecrets);
            String desc = redactSecrets ? maskSensitive(l.description()) : l.description();
            sb.append("| ").append(i + 1)
                    .append(" | ").append(l.category().displayName())
                    .append(" | ").append(l.confidence().displayName())
                    .append(" | ").append(String.format("%.2f", l.confidenceScore()))
                    .append(" | ").append(l.severity().displayName())
                    .append(" | 0x").append(Long.toHexString(l.address()))
                    .append(" | ").append(l.symbol() != null ? l.symbol() : "-")
                    .append(" | `").append(target.replace("`", "'")).append("`")
                    .append(" | ").append(desc.replace("|", "\\|"))
                    .append(" |\n");
        }
        return sb.toString();
    }

    /**
     * Serializes ranked leads to SARIF 2.1.0 format.
     */
    public String toSarif(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
        sb.append("  \"version\": \"2.1.0\",\n");
        sb.append("  \"runs\": [\n");
        sb.append("    {\n");
        sb.append("      \"tool\": {\n");
        sb.append("        \"driver\": {\n");
        sb.append("          \"name\": \"Embedra Security Leads Analyzer\",\n");
        sb.append("          \"version\": \"1.0.0\"\n");
        sb.append("        }\n");
        sb.append("      },\n");
        sb.append("      \"results\": [\n");
        for (int i = 0; i < rankedLeads.size(); i++) {
            SecurityLead l = rankedLeads.get(i);
            String desc = redactSecrets ? maskSensitive(l.description()) : l.description();
            String level = switch (l.severity()) {
                case CRITICAL, HIGH -> "error";
                case MEDIUM -> "warning";
                case LOW, INFO -> "note";
            };
            sb.append("        {\n");
            sb.append("          \"ruleId\": \"EMBEDRA-LEAD-").append(l.category().name()).append("\",\n");
            sb.append("          \"level\": \"").append(level).append("\",\n");
            sb.append("          \"message\": {\n");
            sb.append("            \"text\": \"").append(escapeJson(desc)).append("\"\n");
            sb.append("          },\n");
            sb.append("          \"locations\": [\n");
            sb.append("            {\n");
            sb.append("              \"physicalLocation\": {\n");
            sb.append("                \"address\": {\n");
            sb.append("                  \"absoluteAddress\": ").append(l.address()).append("\n");
            sb.append("                }\n");
            sb.append("              }\n");
            sb.append("            }\n");
            sb.append("          ]\n");
            sb.append("        }").append(i < rankedLeads.size() - 1 ? "," : "").append("\n");
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
