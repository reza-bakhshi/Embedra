package io.github.rezabakhshi.embedra.analyzers.logging;

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Aggregated report of discovered logging, assert, and panic call sites with structured export (AN-004, AN-008).
 */
public final class LoggingAnalysisReport {

    private static final Pattern SENSITIVE_PATTERN = Pattern.compile(
            "(?i)(password|secret|token|api[_-]?key|credential|private[_-]?key|auth)"
                    + "([:=]|\\s+is\\s+|\\s+as\\s+)?\\s*([A-Za-z0-9+/=_-]{8,})");

    private final List<LoggingCallSite> callSites;

    public LoggingAnalysisReport(List<LoggingCallSite> callSites) {
        Objects.requireNonNull(callSites, "callSites must not be null");
        this.callSites = List.copyOf(callSites);
    }

    public List<LoggingCallSite> callSites() {
        return callSites;
    }

    public int totalCount() {
        return callSites.size();
    }

    /**
     * Returns count of call sites grouped by {@link DiagnosticLogLevel}.
     */
    public Map<DiagnosticLogLevel, Integer> countByLevel() {
        Map<DiagnosticLogLevel, Integer> map = new EnumMap<>(DiagnosticLogLevel.class);
        for (DiagnosticLogLevel level : DiagnosticLogLevel.values()) {
            map.put(level, 0);
        }
        for (LoggingCallSite site : callSites) {
            map.put(site.level(), map.get(site.level()) + 1);
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Serializes report to JSON.
     */
    public String toJson(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"totalCallSites\": ").append(callSites.size()).append(",\n");
        sb.append("  \"redacted\": ").append(redactSecrets).append(",\n");
        sb.append("  \"callSites\": [\n");
        for (int i = 0; i < callSites.size(); i++) {
            LoggingCallSite s = callSites.get(i);
            String fmt = s.formatString() != null ? s.formatString().rawText() : "";
            if (redactSecrets) {
                fmt = maskSensitive(fmt);
            }
            sb.append("    {\n");
            sb.append("      \"address\": ").append(s.callInstructionAddress()).append(",\n");
            sb.append("      \"targetFunctionAddress\": ").append(s.targetFunctionAddress()).append(",\n");
            sb.append("      \"targetSymbol\": \"").append(escapeJson(s.targetSymbol())).append("\",\n");
            sb.append("      \"level\": \"").append(s.level().name()).append("\",\n");
            sb.append("      \"formatString\": \"").append(escapeJson(fmt)).append("\",\n");
            sb.append("      \"expectedArgs\": ").append(
                    s.formatString() != null ? s.formatString().expectedArgumentCount() : 0).append(",\n");
            sb.append("      \"confidence\": \"").append(escapeJson(s.confidence())).append("\",\n");
            String fileName = s.fileName() != null ? s.fileName() : "";
            sb.append("      \"fileName\": \"").append(escapeJson(fileName)).append("\",\n");
            String lineNum = s.lineNumber() != null ? s.lineNumber() : "";
            sb.append("      \"lineNumber\": \"").append(escapeJson(lineNum)).append("\",\n");
            String expr = s.expression() != null ? s.expression() : "";
            sb.append("      \"expression\": \"").append(escapeJson(expr)).append("\",\n");
            sb.append("      \"explanation\": \"").append(escapeJson(s.explanation())).append("\"\n");
            sb.append("    }").append(i < callSites.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Serializes report to Markdown table.
     */
    public String toMarkdown(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Embedra Logging & Diagnostics Recovery Report\n\n");
        sb.append("**Total Call Sites:** ").append(callSites.size()).append("\n\n");
        sb.append("| Call Address | Level | Target | Format / Assertion | Source File:Line | Confidence |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for (LoggingCallSite s : callSites) {
            String fmt = s.formatString() != null ? s.formatString().rawText() : "";
            if (fmt.isBlank() && s.expression() != null) {
                fmt = "assert(" + s.expression() + ")";
            }
            if (redactSecrets) {
                fmt = maskSensitive(fmt);
            }
            String fileLine = "-";
            if (s.fileName() != null) {
                fileLine = s.fileName() + (s.lineNumber() != null ? ":" + s.lineNumber() : "");
            }
            sb.append("| `0x").append(Long.toHexString(s.callInstructionAddress()).toUpperCase()).append("` | ")
                    .append(s.level().name()).append(" | `")
                    .append(escapeMarkdown(s.targetSymbol().isBlank() ? "-" : s.targetSymbol())).append("` | `")
                    .append(escapeMarkdown(fmt)).append("` | ")
                    .append(escapeMarkdown(fileLine)).append(" | ")
                    .append(s.confidence()).append(" |\n");
        }
        return sb.toString();
    }

    /**
     * Serializes report to SARIF 2.1.0 static analysis format.
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
        for (int i = 0; i < callSites.size(); i++) {
            LoggingCallSite s = callSites.get(i);
            String level = switch (s.level()) {
                case PANIC, ASSERT, ERROR -> "error";
                case WARNING -> "warning";
                case INFO, DEBUG -> "note";
            };
            String text = s.summary();
            if (redactSecrets) {
                text = maskSensitive(text);
            }
            sb.append("        {\n");
            sb.append("          \"ruleId\": \"EMBEDRA_LOG_").append(s.level().name()).append("\",\n");
            sb.append("          \"level\": \"").append(level).append("\",\n");
            sb.append("          \"message\": {\n");
            sb.append("            \"text\": \"").append(escapeJson(text)).append("\"\n");
            sb.append("          }\n");
            sb.append("        }").append(i < callSites.size() - 1 ? "," : "").append("\n");
        }
        sb.append("      ]\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String maskSensitive(String text) {
        if (text == null) {
            return "";
        }
        return SENSITIVE_PATTERN.matcher(text).replaceAll("$1$2***REDACTED***");
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
