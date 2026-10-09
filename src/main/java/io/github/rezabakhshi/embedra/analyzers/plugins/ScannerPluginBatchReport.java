package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFinding;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Aggregated execution report for a batch of scanner plugins (AN-006, AN-008, AN-009).
 */
public record ScannerPluginBatchReport(
        List<ScannerPluginExecutionResult> results,
        Duration totalDuration,
        int totalFindingsCount,
        int successCount,
        int timeoutCount,
        int errorCount) {

    public ScannerPluginBatchReport {
        results = results == null ? List.of() : List.copyOf(results);
        totalDuration = totalDuration == null ? Duration.ZERO : totalDuration;
    }

    /**
     * Builds a batch report from execution results.
     */
    public static ScannerPluginBatchReport of(List<ScannerPluginExecutionResult> results, Duration totalDuration) {
        Objects.requireNonNull(results, "results must not be null");
        int totalFindings = 0;
        int success = 0;
        int timeouts = 0;
        int errors = 0;

        for (ScannerPluginExecutionResult res : results) {
            totalFindings += res.findings().size();
            switch (res.status()) {
                case SUCCESS, LIMIT_EXCEEDED -> success++;
                case TIMEOUT -> timeouts++;
                case EXECUTION_ERROR, RESOURCE_EXHAUSTED -> errors++;
                default -> { /* ignored */ }
            }
        }

        return new ScannerPluginBatchReport(results, totalDuration, totalFindings, success, timeouts, errors);
    }

    /**
     * Extracts all findings across all successful plugins converted to canonical {@link UnifiedFinding}s.
     */
    public List<UnifiedFinding> toUnifiedFindings() {
        List<UnifiedFinding> list = new ArrayList<>();
        for (ScannerPluginExecutionResult r : results) {
            for (ScannerPluginFinding f : r.findings()) {
                list.add(f.toUnifiedFinding());
            }
        }
        return Collections.unmodifiableList(list);
    }

    /**
     * Serializes this report to JSON with secret redaction support (AN-008).
     */
    public String toJson(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"totalDurationMs\": ").append(totalDuration.toMillis()).append(",\n");
        sb.append("  \"totalFindings\": ").append(totalFindingsCount).append(",\n");
        sb.append("  \"successCount\": ").append(successCount).append(",\n");
        sb.append("  \"timeoutCount\": ").append(timeoutCount).append(",\n");
        sb.append("  \"errorCount\": ").append(errorCount).append(",\n");
        sb.append("  \"results\": [\n");

        for (int i = 0; i < results.size(); i++) {
            ScannerPluginExecutionResult res = results.get(i);
            sb.append("    {\n");
            sb.append("      \"pluginId\": \"").append(escapeJson(res.pluginId())).append("\",\n");
            sb.append("      \"status\": \"").append(res.status().name()).append("\",\n");
            sb.append("      \"durationMs\": ").append(res.duration().toMillis()).append(",\n");
            sb.append("      \"bytesScanned\": ").append(res.bytesScanned()).append(",\n");
            if (res.diagnosticMessage() != null) {
                sb.append("      \"diagnostic\": \"").append(escapeJson(res.diagnosticMessage())).append("\",\n");
            }
            sb.append("      \"findings\": [\n");
            for (int j = 0; j < res.findings().size(); j++) {
                ScannerPluginFinding f = res.findings().get(j);
                sb.append("        {\n");
                sb.append("          \"id\": \"").append(escapeJson(f.findingId())).append("\",\n");
                sb.append("          \"category\": \"").append(f.category().name()).append("\",\n");
                sb.append("          \"severity\": \"").append(f.severity().name()).append("\",\n");
                sb.append("          \"confidence\": \"").append(f.confidence().name()).append("\",\n");
                sb.append("          \"address\": \"0x").append(Long.toHexString(f.address())).append("\",\n");
                sb.append("          \"target\": \"").append(escapeJson(f.maskedTarget(redactSecrets))).append("\",\n");
                sb.append("          \"secret\": ").append(f.secret()).append("\n");
                sb.append("        }").append(j < res.findings().size() - 1 ? "," : "").append("\n");
            }
            sb.append("      ]\n");
            sb.append("    }").append(i < results.size() - 1 ? "," : "").append("\n");
        }

        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Serializes this report to Markdown format.
     */
    public String toMarkdown(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Scanner Plugin Execution Report\n\n");
        sb.append(String.format(Locale.ROOT, "- **Total Duration:** %d ms\n", totalDuration.toMillis()));
        sb.append(String.format(Locale.ROOT, "- **Total Findings:** %d\n", totalFindingsCount));
        sb.append(String.format(Locale.ROOT, "- **Successful Plugins:** %d\n", successCount));
        sb.append(String.format(Locale.ROOT, "- **Timed Out Plugins:** %d\n", timeoutCount));
        sb.append(String.format(Locale.ROOT, "- **Errored Plugins:** %d\n\n", errorCount));

        sb.append("## Plugin Summary\n\n");
        sb.append("| Plugin ID | Status | Duration | Findings | Diagnostic |\n");
        sb.append("|-----------|--------|----------|----------|------------|\n");
        for (ScannerPluginExecutionResult r : results) {
            sb.append(String.format(Locale.ROOT, "| `%s` | `%s` | %d ms | %d | %s |\n",
                    r.pluginId(),
                    r.status().name(),
                    r.duration().toMillis(),
                    r.findings().size(),
                    r.diagnosticMessage() != null ? r.diagnosticMessage() : "-"));
        }

        sb.append("\n## Discovered Findings\n\n");
        sb.append("| Address | Plugin | Severity | Target | Explanation |\n");
        sb.append("|---------|--------|----------|--------|-------------|\n");
        for (ScannerPluginExecutionResult r : results) {
            for (ScannerPluginFinding f : r.findings()) {
                sb.append(String.format(Locale.ROOT, "| `0x%08X` | `%s` | `%s` | `%s` | %s |\n",
                        f.address(),
                        f.pluginId(),
                        f.severity().name(),
                        escapeMd(f.maskedTarget(redactSecrets)),
                        escapeMd(f.explanation())));
            }
        }

        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String escapeMd(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("|", "\\|").replace("\n", " ");
    }
}
