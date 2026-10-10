package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CryptoCorpusBenchmarkTest {

    private CryptoCorpusBenchmark benchmark;

    private CryptoCorpus corpus;

    private ParserLimits limits;

    @BeforeEach
    void setUp() {
        benchmark = new CryptoCorpusBenchmark();
        corpus = CryptoCorpus.defaultCorpus();
        limits = ParserLimits.defaults();
    }

    @Test
    void runsComprehensiveBenchmarkAndVerifiesZeroAn003Violations() throws Exception {
        CryptoBenchmarkReport report = benchmark.runBenchmark(corpus, limits, CancellationToken.none());

        assertNotNull(report);
        assertTrue(report.passesValidation(), "Benchmark must pass with 0 invariant errors: "
                + report.validationErrors());
        assertEquals(31, report.totalSamples());
        assertEquals(12, report.positiveSamples());
        assertEquals(15, report.negativeSamples());
        assertEquals(4, report.unsupportedSamples());
        // Verify per-detector performance metrics
        Map<CryptoDetectorType, DetectorEvaluation> detectors = report.detectorEvaluations();
        assertEquals(CryptoDetectorType.values().length, detectors.size());

        for (CryptoDetectorType dt : CryptoDetectorType.values()) {
            DetectorEvaluation de = detectors.get(dt);
            assertNotNull(de, "Detector evaluation must exist for " + dt);
            assertTrue(de.precision() >= 0.90, dt + " precision must be >= 0.90, was " + de.precision());
            assertTrue(de.recall() >= 0.90, dt + " recall must be >= 0.90, was " + de.recall());
            assertTrue(de.falsePositiveRate() <= 0.05, dt + " FPR must be <= 0.05, was " + de.falsePositiveRate());
            assertTrue(de.f1Score() >= 0.90, dt + " F1 must be >= 0.90, was " + de.f1Score());
        }

        // Verify confidence calibration
        Map<CryptoConfidence, ConfidenceCalibration> calibrations = report.confidenceCalibrations();
        ConfidenceCalibration confirmedCalib = calibrations.get(CryptoConfidence.CONFIRMED);
        assertNotNull(confirmedCalib);
        assertTrue(confirmedCalib.totalFindings() > 0);
        assertEquals(0, confirmedCalib.falsePositives());
        assertEquals(1.0, confirmedCalib.precision(), 0.0001);

        ConfidenceCalibration likelyCalib = calibrations.get(CryptoConfidence.LIKELY);
        assertNotNull(likelyCalib);
        assertTrue(likelyCalib.precision() >= 0.95);

        // Verify unsupported cases
        assertEquals(4, report.unsupportedCases().size());
        assertTrue(report.unsupportedCases().stream()
                .anyMatch(uc -> uc.targetAlgorithm() == CryptoAlgorithm.CHACHA20));
        assertTrue(report.unsupportedCases().stream()
                .anyMatch(uc -> uc.targetAlgorithm() == CryptoAlgorithm.SECURE_ELEMENT));
        assertTrue(report.unsupportedCases().stream()
                .anyMatch(uc -> uc.targetAlgorithm() == CryptoAlgorithm.AES_128
                        && uc.reason() == UnsupportedReason.COPROCESSOR_ISOLATED_FIRMWARE));
        assertTrue(report.unsupportedCases().stream()
                .anyMatch(uc -> uc.targetAlgorithm() == CryptoAlgorithm.AES_128
                        && uc.reason() == UnsupportedReason.CUSTOM_INLINED_WITHOUT_CONSTANTS));
    }

    @Test
    void generatesValidJsonAndMarkdownReportsWithoutSecretLeaking() throws Exception {
        CryptoBenchmarkReport report = benchmark.runBenchmark(corpus, limits, CancellationToken.none());

        // 1. JSON report validation
        String json = report.toJson();
        assertNotNull(json);
        assertTrue(json.contains("\"totalSamples\": 31"));
        assertTrue(json.contains("\"passed\": true"));
        assertTrue(json.contains("\"CONSTANT_TABLE\""));
        assertTrue(json.contains("\"LIBRARY_SIGNATURE\""));
        assertTrue(json.contains("\"HARDWARE_PERIPHERAL\""));
        assertTrue(json.contains("\"unsupportedCases\""));

        // AN-008: Secrets must not be leaked in plain text in benchmark reports
        assertFalse(json.contains("5a3b8c1d4e2f9076123456789abcdef0"), "Raw secret key leaked in JSON report");

        // 2. Markdown report validation
        String md = report.toMarkdown();
        assertNotNull(md);
        assertTrue(md.contains("# Cryptographic Detector Evaluation & Benchmark Matrix"));
        assertTrue(md.contains("## Corpus Composition"));
        assertTrue(md.contains("## Per-Detector Performance Matrix"));
        assertTrue(md.contains("## Confidence Calibration Across Tiers"));
        assertTrue(md.contains("## Explicit Unsupported Cases & Limitations"));
        assertFalse(md.contains("5a3b8c1d4e2f9076123456789abcdef0"), "Raw secret key leaked in Markdown report");
    }

    @Test
    void respectsCancellation() {
        CancellationToken cancelled = () -> true;

        assertThrows(DiagnosticException.class, () ->
                benchmark.runBenchmark(corpus, limits, cancelled));
    }

    @Test
    void respectsInputByteLimits() {
        ParserLimits tinyLimit = new ParserLimits(16, 1000, 1000, 1000, 100, Duration.ofSeconds(10));

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                benchmark.runBenchmark(corpus, tinyLimit, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }
}
