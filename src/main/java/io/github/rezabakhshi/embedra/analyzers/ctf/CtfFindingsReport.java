package io.github.rezabakhshi.embedra.analyzers.ctf;

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Report containing discovered CTF findings with structured export support (AN-006, AN-008).
 *
 * <p>Supports JSON, Markdown, and SARIF export with mandatory secret redaction by default.</p>
 */
public final class CtfFindingsReport {

    private final List<CtfEntity> entities;

    public CtfFindingsReport(List<CtfEntity> entities) {
        Objects.requireNonNull(entities, "entities must not be null");
        this.entities = List.copyOf(entities);
    }

    public List<CtfEntity> entities() {
        return entities;
    }

    public int totalCount() {
        return entities.size();
    }

    /**
     * Aggregates findings count grouped by {@link CtfEntityCategory}.
     */
    public Map<CtfEntityCategory, Integer> countByCategory() {
        Map<CtfEntityCategory, Integer> counts = new EnumMap<>(CtfEntityCategory.class);
        for (CtfEntityCategory cat : CtfEntityCategory.values()) {
            counts.put(cat, 0);
        }
        for (CtfEntity entity : entities) {
            counts.put(entity.category(), counts.get(entity.category()) + 1);
        }
        return Collections.unmodifiableMap(counts);
    }

    /**
     * Aggregates findings count grouped by {@link CtfSeverity}.
     */
    public Map<CtfSeverity, Integer> countBySeverity() {
        Map<CtfSeverity, Integer> counts = new EnumMap<>(CtfSeverity.class);
        for (CtfSeverity sev : CtfSeverity.values()) {
            counts.put(sev, 0);
        }
        for (CtfEntity entity : entities) {
            counts.put(entity.severity(), counts.get(entity.severity()) + 1);
        }
        return Collections.unmodifiableMap(counts);
    }

    /**
     * Serializes findings to a JSON document.
     */
    public String toJson(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"totalFindings\": ").append(entities.size()).append(",\n");
        sb.append("  \"redacted\": ").append(redactSecrets).append(",\n");
        sb.append("  \"findings\": [\n");
        for (int i = 0; i < entities.size(); i++) {
            CtfEntity e = entities.get(i);
            String val = redactSecrets ? e.maskedValue() : e.value();
            sb.append("    {\n");
            sb.append("      \"id\": \"").append(escapeJson(e.id())).append("\",\n");
            sb.append("      \"category\": \"").append(e.category().name()).append("\",\n");
            sb.append("      \"type\": \"").append(e.type().name()).append("\",\n");
            sb.append("      \"severity\": \"").append(e.severity().name()).append("\",\n");
            sb.append("      \"confidence\": \"").append(e.confidence().name()).append("\",\n");
            sb.append("      \"address\": ").append(e.address()).append(",\n");
            sb.append("      \"length\": ").append(e.length()).append(",\n");
            sb.append("      \"value\": \"").append(escapeJson(val)).append("\",\n");
            sb.append("      \"explanation\": \"").append(escapeJson(e.explanation())).append("\",\n");
            sb.append("      \"secret\": ").append(e.isSecret()).append("\n");
            sb.append("    }").append(i < entities.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Serializes findings to a Markdown summary table.
     */
    public String toMarkdown(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Embedra CTF & Firmware Findings\n\n");
        sb.append("**Total Findings:** ").append(entities.size()).append("\n\n");
        sb.append("| Address | Category | Type | Severity | Value | Explanation |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for (CtfEntity e : entities) {
            String val = redactSecrets ? e.maskedValue() : e.value();
            sb.append("| `0x").append(Long.toHexString(e.address()).toUpperCase()).append("` | ")
                    .append(e.category().name()).append(" | ")
                    .append(e.type().name()).append(" | ")
                    .append(e.severity().name()).append(" | `")
                    .append(escapeMarkdown(val)).append("` | ")
                    .append(escapeMarkdown(e.explanation())).append(" |\n");
        }
        return sb.toString();
    }

    /**
     * Serializes findings into a SARIF-compatible static analysis format (AN-008).
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
        sb.append("          \"name\": \"Embedra\",\n");
        sb.append("          \"informationUri\": \"https://github.com/rezabakhshi/embedra\"\n");
        sb.append("        }\n");
        sb.append("      },\n");
        sb.append("      \"results\": [\n");
        for (int i = 0; i < entities.size(); i++) {
            CtfEntity e = entities.get(i);
            String val = redactSecrets ? e.maskedValue() : e.value();
            String level = switch (e.severity()) {
                case HIGH -> "error";
                case MEDIUM -> "warning";
                case LOW, INFO -> "note";
            };
            sb.append("        {\n");
            sb.append("          \"ruleId\": \"EMBEDRA_").append(e.type().name()).append("\",\n");
            sb.append("          \"level\": \"").append(level).append("\",\n");
            sb.append("          \"message\": {\n");
            sb.append("            \"text\": \"").append(escapeJson(e.explanation() + ": " + val)).append("\"\n");
            sb.append("          }\n");
            sb.append("        }").append(i < entities.size() - 1 ? "," : "").append("\n");
        }
        sb.append("      ]\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String escapeJson(String str) {
        if (str == null) {
            return "";
        }
        return str.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String escapeMarkdown(String str) {
        if (str == null) {
            return "";
        }
        return str.replace("|", "\\|").replace("\n", " ").replace("\r", "");
    }
}
