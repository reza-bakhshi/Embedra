package io.github.rezabakhshi.embedra.analyzers.crypto.fusion;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Structured report of findings identified by the layered cryptographic analysis pipeline (AN-006, AN-008).
 *
 * <p>Supports JSON, Markdown, and SARIF export with secret masking enabled by default (AN-008).</p>
 */
public final class CryptoAnalysisReport {

    private final List<CryptoFinding> findings;

    public CryptoAnalysisReport(List<CryptoFinding> findings) {
        Objects.requireNonNull(findings, "findings must not be null");
        this.findings = List.copyOf(findings);
    }

    public List<CryptoFinding> findings() {
        return findings;
    }

    public int totalCount() {
        return findings.size();
    }

    public Map<CryptoCategory, Integer> countByCategory() {
        Map<CryptoCategory, Integer> counts = new EnumMap<>(CryptoCategory.class);
        for (CryptoCategory cat : CryptoCategory.values()) {
            counts.put(cat, 0);
        }
        for (CryptoFinding f : findings) {
            counts.put(f.category(), counts.get(f.category()) + 1);
        }
        return Collections.unmodifiableMap(counts);
    }

    public Map<CryptoAlgorithm, Integer> countByAlgorithm() {
        Map<CryptoAlgorithm, Integer> counts = new EnumMap<>(CryptoAlgorithm.class);
        for (CryptoAlgorithm alg : CryptoAlgorithm.values()) {
            counts.put(alg, 0);
        }
        for (CryptoFinding f : findings) {
            counts.put(f.algorithm(), counts.get(f.algorithm()) + 1);
        }
        return Collections.unmodifiableMap(counts);
    }

    public Map<CryptoConfidence, Integer> countByConfidence() {
        Map<CryptoConfidence, Integer> counts = new EnumMap<>(CryptoConfidence.class);
        for (CryptoConfidence conf : CryptoConfidence.values()) {
            counts.put(conf, 0);
        }
        for (CryptoFinding f : findings) {
            counts.put(f.confidence(), counts.get(f.confidence()) + 1);
        }
        return Collections.unmodifiableMap(counts);
    }

    public String toJson() {
        return toJson(true);
    }

    public String toJson(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"totalFindings\": ").append(findings.size()).append(",\n");
        sb.append("  \"redacted\": ").append(redactSecrets).append(",\n");
        sb.append("  \"findings\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            CryptoFinding f = findings.get(i);
            String val = redactSecrets ? f.maskedValue() : f.rawValue();
            String layers = f.evidenceLayers().stream()
                    .map(CryptoEvidenceLayer::name)
                    .sorted()
                    .collect(Collectors.joining("\", \"", "[\"", "\"]"));

            sb.append("    {\n");
            sb.append("      \"id\": \"").append(escapeJson(f.id())).append("\",\n");
            sb.append("      \"category\": \"").append(f.category().name()).append("\",\n");
            sb.append("      \"algorithm\": \"").append(f.algorithm().name()).append("\",\n");
            sb.append("      \"confidence\": \"").append(f.confidence().name()).append("\",\n");
            sb.append("      \"evidenceLayers\": ").append(layers).append(",\n");
            sb.append("      \"address\": ").append(f.address()).append(",\n");
            sb.append("      \"length\": ").append(f.length()).append(",\n");
            sb.append("      \"value\": \"").append(escapeJson(val)).append("\",\n");
            sb.append("      \"explanation\": \"").append(escapeJson(f.explanation())).append("\",\n");
            sb.append("      \"isEncryption\": ").append(f.isEncryption()).append(",\n");
            sb.append("      \"secret\": ").append(f.isSecret()).append("\n");
            sb.append("    }").append(i < findings.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    public String toMarkdown() {
        return toMarkdown(true);
    }

    public String toMarkdown(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Embedra Cryptographic Analysis Report\n\n");
        sb.append("**Total Findings:** ").append(findings.size()).append("\n\n");
        sb.append("| Address | Category | Algorithm | Confidence | Value | Explanation |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for (CryptoFinding f : findings) {
            String val = redactSecrets ? f.maskedValue() : f.rawValue();
            sb.append("| `0x").append(Long.toHexString(f.address()).toUpperCase()).append("` | ")
                    .append(f.category().displayName()).append(" | ")
                    .append(f.algorithm().displayName()).append(" | ")
                    .append(f.confidence().displayName()).append(" | `")
                    .append(escapeMarkdown(val)).append("` | ")
                    .append(escapeMarkdown(f.explanation())).append(" |\n");
        }
        return sb.toString();
    }

    public String toSarif() {
        return toSarif(true);
    }

    public String toSarif(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
        sb.append("  \"version\": \"2.1.0\",\n");
        sb.append("  \"runs\": [\n");
        sb.append("    {\n");
        sb.append("      \"tool\": {\n");
        sb.append("        \"driver\": {\n");
        sb.append("          \"name\": \"Embedra Crypto Pipeline\",\n");
        sb.append("          \"informationUri\": \"https://github.com/rezabakhshi/embedra\"\n");
        sb.append("        }\n");
        sb.append("      },\n");
        sb.append("      \"results\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            CryptoFinding f = findings.get(i);
            String val = redactSecrets ? f.maskedValue() : f.rawValue();
            String level = switch (f.confidence()) {
                case CONFIRMED, LIKELY -> "warning";
                case PLAUSIBLE, LEAD -> "note";
            };
            sb.append("        {\n");
            sb.append("          \"ruleId\": \"EMBEDRA_CRYPTO_").append(f.algorithm().name()).append("\",\n");
            sb.append("          \"level\": \"").append(level).append("\",\n");
            sb.append("          \"message\": {\n");
            sb.append("            \"text\": \"").append(escapeJson(f.explanation() + " [" + val + "]")).append("\"\n");
            sb.append("          }\n");
            sb.append("        }").append(i < findings.size() - 1 ? "," : "").append("\n");
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
