package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable report of cryptographic detector benchmark metrics across positive and negative corpora (AN-015).
 *
 * <p>Provides structured machine-readable JSON and human-readable Markdown evaluation matrices.</p>
 */
public final class CryptoBenchmarkReport {

    private final int totalSamples;

    private final int positiveSamples;

    private final int negativeSamples;

    private final int unsupportedSamples;

    private final Map<CryptoDetectorType, DetectorEvaluation> detectorEvaluations;

    private final Map<CryptoAlgorithm, AlgorithmEvaluation> algorithmEvaluations;

    private final Map<CryptoConfidence, ConfidenceCalibration> confidenceCalibrations;

    private final List<UnsupportedCase> unsupportedCases;

    private final List<String> validationErrors;

    public CryptoBenchmarkReport(
            int totalSamples,
            int positiveSamples,
            int negativeSamples,
            int unsupportedSamples,
            Map<CryptoDetectorType, DetectorEvaluation> detectorEvaluations,
            Map<CryptoAlgorithm, AlgorithmEvaluation> algorithmEvaluations,
            Map<CryptoConfidence, ConfidenceCalibration> confidenceCalibrations,
            List<UnsupportedCase> unsupportedCases,
            List<String> validationErrors) {

        this.totalSamples = totalSamples;
        this.positiveSamples = positiveSamples;
        this.negativeSamples = negativeSamples;
        this.unsupportedSamples = unsupportedSamples;

        Objects.requireNonNull(detectorEvaluations, "detectorEvaluations must not be null");
        Objects.requireNonNull(algorithmEvaluations, "algorithmEvaluations must not be null");
        Objects.requireNonNull(confidenceCalibrations, "confidenceCalibrations must not be null");

        this.detectorEvaluations = Collections.unmodifiableMap(new EnumMap<>(detectorEvaluations));
        this.algorithmEvaluations = Collections.unmodifiableMap(new EnumMap<>(algorithmEvaluations));
        this.confidenceCalibrations = Collections.unmodifiableMap(new EnumMap<>(confidenceCalibrations));
        this.unsupportedCases = unsupportedCases == null ? List.of() : List.copyOf(unsupportedCases);
        this.validationErrors = validationErrors == null ? List.of() : List.copyOf(validationErrors);
    }

    public int totalSamples() {
        return totalSamples;
    }

    public int positiveSamples() {
        return positiveSamples;
    }

    public int negativeSamples() {
        return negativeSamples;
    }

    public int unsupportedSamples() {
        return unsupportedSamples;
    }

    public Map<CryptoDetectorType, DetectorEvaluation> detectorEvaluations() {
        return detectorEvaluations;
    }

    public Map<CryptoAlgorithm, AlgorithmEvaluation> algorithmEvaluations() {
        return algorithmEvaluations;
    }

    public Map<CryptoConfidence, ConfidenceCalibration> confidenceCalibrations() {
        return confidenceCalibrations;
    }

    public List<UnsupportedCase> unsupportedCases() {
        return unsupportedCases;
    }

    public List<String> validationErrors() {
        return validationErrors;
    }

    public boolean passesValidation() {
        return validationErrors.isEmpty();
    }

    /**
     * Serializes benchmark results to machine-readable JSON format (AN-008, AN-015).
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"corpus\": {\n");
        sb.append("    \"totalSamples\": ").append(totalSamples).append(",\n");
        sb.append("    \"positiveSamples\": ").append(positiveSamples).append(",\n");
        sb.append("    \"negativeSamples\": ").append(negativeSamples).append(",\n");
        sb.append("    \"unsupportedSamples\": ").append(unsupportedSamples).append("\n");
        sb.append("  },\n");

        sb.append("  \"validation\": {\n");
        sb.append("    \"passed\": ").append(passesValidation()).append(",\n");
        sb.append("    \"errors\": [");
        for (int i = 0; i < validationErrors.size(); i++) {
            sb.append("\n      \"").append(escapeJson(validationErrors.get(i))).append("\"");
            if (i < validationErrors.size() - 1) {
                sb.append(",");
            }
        }
        if (!validationErrors.isEmpty()) {
            sb.append("\n    ");
        }
        sb.append("]\n");
        sb.append("  },\n");

        sb.append("  \"detectors\": {\n");
        List<CryptoDetectorType> detectors = List.copyOf(detectorEvaluations.keySet());
        for (int i = 0; i < detectors.size(); i++) {
            CryptoDetectorType dt = detectors.get(i);
            DetectorEvaluation de = detectorEvaluations.get(dt);
            sb.append("    \"").append(dt.name()).append("\": {\n");
            sb.append("      \"name\": \"").append(escapeJson(dt.displayName())).append("\",\n");
            sb.append("      \"truePositives\": ").append(de.truePositives()).append(",\n");
            sb.append("      \"falsePositives\": ").append(de.falsePositives()).append(",\n");
            sb.append("      \"trueNegatives\": ").append(de.trueNegatives()).append(",\n");
            sb.append("      \"falseNegatives\": ").append(de.falseNegatives()).append(",\n");
            sb.append(String.format(Locale.ROOT, "      \"precision\": %.4f,\n", de.precision()));
            sb.append(String.format(Locale.ROOT, "      \"recall\": %.4f,\n", de.recall()));
            sb.append(String.format(Locale.ROOT, "      \"falsePositiveRate\": %.4f,\n", de.falsePositiveRate()));
            sb.append(String.format(Locale.ROOT, "      \"f1Score\": %.4f,\n", de.f1Score()));
            sb.append("      \"confidenceDistribution\": {\n");
            List<CryptoConfidence> confs = List.of(CryptoConfidence.values());
            for (int ci = 0; ci < confs.size(); ci++) {
                CryptoConfidence c = confs.get(ci);
                int count = de.confidenceDistribution().getOrDefault(c, 0);
                sb.append("        \"").append(c.name()).append("\": ").append(count);
                if (ci < confs.size() - 1) {
                    sb.append(",");
                }
                sb.append("\n");
            }
            sb.append("      }\n");
            sb.append("    }").append(i < detectors.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  },\n");

        sb.append("  \"confidenceCalibration\": {\n");
        List<CryptoConfidence> confs = List.of(CryptoConfidence.values());
        for (int i = 0; i < confs.size(); i++) {
            CryptoConfidence c = confs.get(i);
            ConfidenceCalibration cc = confidenceCalibrations.getOrDefault(
                    c, new ConfidenceCalibration(c, 0, 0, 0));
            sb.append("    \"").append(c.name()).append("\": {\n");
            sb.append("      \"totalFindings\": ").append(cc.totalFindings()).append(",\n");
            sb.append("      \"truePositives\": ").append(cc.truePositives()).append(",\n");
            sb.append("      \"falsePositives\": ").append(cc.falsePositives()).append(",\n");
            sb.append(String.format(Locale.ROOT, "      \"precision\": %.4f\n", cc.precision()));
            sb.append("    }").append(i < confs.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  },\n");

        sb.append("  \"unsupportedCases\": [\n");
        for (int i = 0; i < unsupportedCases.size(); i++) {
            UnsupportedCase uc = unsupportedCases.get(i);
            sb.append("    {\n");
            sb.append("      \"sampleId\": \"").append(escapeJson(uc.sampleId())).append("\",\n");
            sb.append("      \"platform\": \"").append(escapeJson(uc.platformName())).append("\",\n");
            sb.append("      \"toolchainOrIsa\": \"").append(escapeJson(uc.toolchainOrIsa())).append("\",\n");
            sb.append("      \"algorithm\": \"").append(uc.targetAlgorithm().name()).append("\",\n");
            sb.append("      \"reason\": \"").append(uc.reason().name()).append("\",\n");
            sb.append("      \"description\": \"").append(escapeJson(uc.description())).append("\",\n");
            sb.append("      \"plannedMitigation\": \"").append(escapeJson(uc.plannedMitigation())).append("\"\n");
            sb.append("    }").append(i < unsupportedCases.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Formats benchmark evaluation into GitHub Flavored Markdown (AN-008, AN-015).
     */
    public String toMarkdown() {
        StringBuilder sb = new StringBuilder();
        sb.append("# Cryptographic Detector Evaluation & Benchmark Matrix\n\n");
        sb.append("Evaluated across positive and negative corpora over "
                + "ESP, STM32, RP2040, and RP2350 ISAs (AN-015).\n\n");

        sb.append("## Corpus Composition\n\n");
        sb.append("| Metric | Count |\n");
        sb.append("|---|---|\n");
        sb.append("| Total Evaluated Samples | ").append(totalSamples).append(" |\n");
        sb.append("| Positive Implementations & Peripherals | ").append(positiveSamples).append(" |\n");
        sb.append("| Adversarial Negative Samples | ").append(negativeSamples).append(" |\n");
        sb.append("| Explicit Unsupported Variants | ").append(unsupportedSamples).append(" |\n");
        sb.append("| Invariant Validation Status | ")
                .append(passesValidation() ? "PASS (0 Invariant Violations)" : "FAIL")
                .append(" |\n\n");

        sb.append("## Per-Detector Performance Matrix\n\n");
        sb.append("| Detector Engine | TP | FP | TN | FN | Precision | Recall | FPR | F1 Score |\n");
        sb.append("|---|---|---|---|---|---|---|---|---|\n");
        List<DetectorEvaluation> sortedDetectors = detectorEvaluations.values().stream()
                .sorted(Comparator.comparing(de -> de.detectorType().name()))
                .toList();
        for (DetectorEvaluation de : sortedDetectors) {
            sb.append(String.format(Locale.ROOT,
                    "| %s | %d | %d | %d | %d | %.2f%% | %.2f%% | %.2f%% | %.4f |\n",
                    de.detectorType().displayName(),
                    de.truePositives(),
                    de.falsePositives(),
                    de.trueNegatives(),
                    de.falseNegatives(),
                    de.precision() * 100.0,
                    de.recall() * 100.0,
                    de.falsePositiveRate() * 100.0,
                    de.f1Score()));
        }
        sb.append("\n");

        sb.append("## Confidence Calibration Across Tiers\n\n");
        sb.append("| Confidence Tier | Total Findings | Corroborated (TP) | Spurious (FP) | Precision |\n");
        sb.append("|---|---|---|---|---|\n");
        for (CryptoConfidence conf : CryptoConfidence.values()) {
            ConfidenceCalibration cc = confidenceCalibrations.getOrDefault(
                    conf, new ConfidenceCalibration(conf, 0, 0, 0));
            sb.append(String.format(Locale.ROOT,
                    "| %s | %d | %d | %d | %.2f%% |\n",
                    conf.displayName(),
                    cc.totalFindings(),
                    cc.truePositives(),
                    cc.falsePositives(),
                    cc.precision() * 100.0));
        }
        sb.append("\n");

        sb.append("## Per-Algorithm Performance Highlights\n\n");
        sb.append("| Algorithm / Primitive | TP | FP | TN | FN | Precision | Recall | F1 Score |\n");
        sb.append("|---|---|---|---|---|---|---|---|\n");
        List<AlgorithmEvaluation> sortedAlgos = algorithmEvaluations.values().stream()
                .filter(ae -> ae.truePositives() > 0 || ae.falsePositives() > 0 || ae.falseNegatives() > 0)
                .sorted(Comparator.comparing(ae -> ae.algorithm().name()))
                .toList();
        for (AlgorithmEvaluation ae : sortedAlgos) {
            sb.append(String.format(Locale.ROOT,
                    "| %s | %d | %d | %d | %d | %.2f%% | %.2f%% | %.4f |\n",
                    ae.algorithm().displayName(),
                    ae.truePositives(),
                    ae.falsePositives(),
                    ae.trueNegatives(),
                    ae.falseNegatives(),
                    ae.precision() * 100.0,
                    ae.recall() * 100.0,
                    ae.f1Score()));
        }
        sb.append("\n");

        sb.append("## Explicit Unsupported Cases & Limitations\n\n");
        sb.append("| Case ID | Platform | ISA / Toolchain | Algorithm | Limitation Category | Mitigation / Plan |\n");
        sb.append("|---|---|---|---|---|---|\n");
        for (UnsupportedCase uc : unsupportedCases) {
            sb.append(String.format(Locale.ROOT,
                    "| %s | %s | %s | %s | %s | %s |\n",
                    uc.sampleId(),
                    uc.platformName(),
                    uc.toolchainOrIsa(),
                    uc.targetAlgorithm().displayName(),
                    uc.reason().description(),
                    uc.plannedMitigation()));
        }
        sb.append("\n");

        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
