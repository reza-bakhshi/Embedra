package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoScanOptions;
import io.github.rezabakhshi.embedra.analyzers.crypto.entropy.EntropyScanner;
import io.github.rezabakhshi.embedra.analyzers.crypto.entropy.LikelyKeyScanner;
import io.github.rezabakhshi.embedra.analyzers.crypto.fusion.CryptoAnalysisPipeline;
import io.github.rezabakhshi.embedra.analyzers.crypto.fusion.CryptoAnalysisReport;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCryptoAnalyzer;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCryptoReport;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareMemoryAccess;
import io.github.rezabakhshi.embedra.analyzers.crypto.signatures.CryptoLibrarySignatureMatcher;
import io.github.rezabakhshi.embedra.analyzers.crypto.signatures.CryptoSignatureMatchReport;
import io.github.rezabakhshi.embedra.analyzers.crypto.tables.CryptoTableDatabase;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Pure evaluation engine measuring per-detector precision, recall, false-positive rate,
 * confidence calibration, and unsupported cases across cryptographic corpora (AN-003, AN-015).
 */
public final class CryptoCorpusBenchmark {

    private final CryptoTableDatabase tableDatabase;

    private final CryptoLibrarySignatureMatcher signatureMatcher;

    private final HardwareCryptoAnalyzer hardwareAnalyzer;

    private final LikelyKeyScanner keyScanner;

    private final EntropyScanner entropyScanner;

    private final CryptoAnalysisPipeline pipeline;

    public CryptoCorpusBenchmark() {
        this(new CryptoTableDatabase(),
                new CryptoLibrarySignatureMatcher(),
                new HardwareCryptoAnalyzer(),
                new LikelyKeyScanner(),
                new EntropyScanner(),
                new CryptoAnalysisPipeline());
    }

    public CryptoCorpusBenchmark(
            CryptoTableDatabase tableDatabase,
            CryptoLibrarySignatureMatcher signatureMatcher,
            HardwareCryptoAnalyzer hardwareAnalyzer,
            LikelyKeyScanner keyScanner,
            EntropyScanner entropyScanner,
            CryptoAnalysisPipeline pipeline) {

        this.tableDatabase = Objects.requireNonNull(tableDatabase, "tableDatabase must not be null");
        this.signatureMatcher = Objects.requireNonNull(signatureMatcher, "signatureMatcher must not be null");
        this.hardwareAnalyzer = Objects.requireNonNull(hardwareAnalyzer, "hardwareAnalyzer must not be null");
        this.keyScanner = Objects.requireNonNull(keyScanner, "keyScanner must not be null");
        this.entropyScanner = Objects.requireNonNull(entropyScanner, "entropyScanner must not be null");
        this.pipeline = Objects.requireNonNull(pipeline, "pipeline must not be null");
    }

    /**
     * Executes the comprehensive benchmark evaluation over the given cryptographic corpus (AN-015).
     */
    public CryptoBenchmarkReport runBenchmark(
            CryptoCorpus corpus,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        Objects.requireNonNull(corpus, "corpus must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();
        long startNanos = System.nanoTime();

        Map<CryptoDetectorType, MutableCounts> detectorCounts = new EnumMap<>(CryptoDetectorType.class);
        Map<CryptoDetectorType, Map<CryptoConfidence, Integer>> detectorConfDist =
                new EnumMap<>(CryptoDetectorType.class);
        for (CryptoDetectorType dt : CryptoDetectorType.values()) {
            detectorCounts.put(dt, new MutableCounts());
            Map<CryptoConfidence, Integer> confMap = new EnumMap<>(CryptoConfidence.class);
            for (CryptoConfidence conf : CryptoConfidence.values()) {
                confMap.put(conf, 0);
            }
            detectorConfDist.put(dt, confMap);
        }

        Map<CryptoAlgorithm, MutableCounts> algorithmCounts = new EnumMap<>(CryptoAlgorithm.class);
        for (CryptoAlgorithm alg : CryptoAlgorithm.values()) {
            algorithmCounts.put(alg, new MutableCounts());
        }

        Map<CryptoConfidence, MutableConfidence> confidenceMap = new EnumMap<>(CryptoConfidence.class);
        for (CryptoConfidence conf : CryptoConfidence.values()) {
            confidenceMap.put(conf, new MutableConfidence());
        }

        List<UnsupportedCase> unsupportedCases = new ArrayList<>();
        List<String> validationErrors = new ArrayList<>();

        int positiveCount = 0;
        int negativeCount = 0;
        int unsupportedCount = 0;
        long totalBytesProcessed = 0;

        for (CryptoCorpusSample sample : corpus.allSamples()) {
            token.throwIfCancellationRequested();
            if (System.nanoTime() - startNanos > limits.maxWallTime().toNanos()) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.LIMIT_EXCEEDED, "Benchmark exceeded wall time limit", null));
            }

            totalBytesProcessed += sample.payload().length;
            if (totalBytesProcessed > limits.maxInputBytes()) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.LIMIT_EXCEEDED, "Benchmark exceeded total byte input limit", null));
            }

            if (sample.classification() == CryptoCorpusClassification.POSITIVE) {
                positiveCount++;
            } else if (sample.classification() == CryptoCorpusClassification.NEGATIVE_ADVERSARIAL) {
                negativeCount++;
            } else if (sample.classification() == CryptoCorpusClassification.UNSUPPORTED_VARIANT) {
                unsupportedCount++;
                sample.optionalUnsupportedCase().ifPresent(unsupportedCases::add);
            }

            // Execute each detector independently on this sample
            Map<CryptoDetectorType, List<CryptoFinding>> detectorOutputs = runDetectors(sample, limits, token);

            // Evaluate findings per detector and per algorithm
            evaluateSample(sample, detectorOutputs, detectorCounts, detectorConfDist,
                    algorithmCounts, confidenceMap, validationErrors);
        }

        // Assemble immutable reports
        Map<CryptoDetectorType, DetectorEvaluation> finalDetectors = new EnumMap<>(CryptoDetectorType.class);
        for (CryptoDetectorType dt : CryptoDetectorType.values()) {
            MutableCounts c = detectorCounts.get(dt);
            finalDetectors.put(dt, new DetectorEvaluation(
                    dt, c.tp, c.fp, c.tn, c.fn, detectorConfDist.get(dt)));
        }

        Map<CryptoAlgorithm, AlgorithmEvaluation> finalAlgos = new EnumMap<>(CryptoAlgorithm.class);
        for (CryptoAlgorithm alg : CryptoAlgorithm.values()) {
            MutableCounts c = algorithmCounts.get(alg);
            finalAlgos.put(alg, new AlgorithmEvaluation(alg, c.tp, c.fp, c.tn, c.fn));
        }

        Map<CryptoConfidence, ConfidenceCalibration> finalConfs = new EnumMap<>(CryptoConfidence.class);
        for (CryptoConfidence conf : CryptoConfidence.values()) {
            MutableConfidence mc = confidenceMap.get(conf);
            finalConfs.put(conf, new ConfidenceCalibration(conf, mc.total, mc.tp, mc.fp));
        }

        return new CryptoBenchmarkReport(
                corpus.allSamples().size(),
                positiveCount,
                negativeCount,
                unsupportedCount,
                finalDetectors,
                finalAlgos,
                finalConfs,
                unsupportedCases,
                validationErrors
        );
    }

    private Map<CryptoDetectorType, List<CryptoFinding>> runDetectors(
            CryptoCorpusSample sample,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        Map<CryptoDetectorType, List<CryptoFinding>> map = new EnumMap<>(CryptoDetectorType.class);
        byte[] payload = sample.payload();
        long baseAddr = sample.baseAddress();

        // 1. Constant Table
        List<CryptoFinding> tableFindings = tableDatabase.scan(payload, baseAddr, limits, token);
        map.put(CryptoDetectorType.CONSTANT_TABLE, tableFindings);

        // 2. Library Signature
        CryptoSignatureMatchReport sigReport = signatureMatcher.scan(
                payload, baseAddr, sample.isa(), limits, token);
        map.put(CryptoDetectorType.LIBRARY_SIGNATURE, sigReport.findings());

        // 3. Hardware Peripheral
        HardwareCryptoReport hwReport = hardwareAnalyzer.analyze(
                sample.platform(), sample.hardwareAccesses(), List.of(), sample.crossProgramRefs(), limits, token);
        map.put(CryptoDetectorType.HARDWARE_PERIPHERAL, hwReport.findings());

        // 4. Vendor ROM API
        HardwareCryptoReport romReport = hardwareAnalyzer.analyze(
                sample.platform(), List.of(), sample.callSites(), List.of(), limits, token);
        map.put(CryptoDetectorType.VENDOR_ROM, romReport.findings());

        // 5. Key Material
        List<CryptoFinding> keyFindings = keyScanner.scan(payload, baseAddr, limits, token);
        map.put(CryptoDetectorType.KEY_MATERIAL, keyFindings);

        // 6. Statistical Entropy
        List<CryptoFinding> entropyFindings = entropyScanner.scan(payload, baseAddr, 7.2, limits, token);
        map.put(CryptoDetectorType.ENTROPY_ANALYSIS, entropyFindings);

        // 7. Fused Pipeline (fuses all layers)
        List<Long> hwAddrs = sample.hardwareAccesses().stream()
                .map(HardwareMemoryAccess::targetAddress)
                .distinct()
                .toList();
        CryptoAnalysisReport pipeReport = pipeline.analyze(
                payload, baseAddr, CryptoScanOptions.defaults(), sample.stringLeads(), hwAddrs, limits, token);

        List<CryptoFinding> fusedCombined = new ArrayList<>(pipeReport.findings());
        fusedCombined.addAll(hwReport.findings());
        fusedCombined.addAll(romReport.findings());
        map.put(CryptoDetectorType.FUSED_PIPELINE, List.copyOf(fusedCombined));

        return map;
    }

    private void evaluateSample(
            CryptoCorpusSample sample,
            Map<CryptoDetectorType, List<CryptoFinding>> detectorOutputs,
            Map<CryptoDetectorType, MutableCounts> detectorCounts,
            Map<CryptoDetectorType, Map<CryptoConfidence, Integer>> detectorConfDist,
            Map<CryptoAlgorithm, MutableCounts> algorithmCounts,
            Map<CryptoConfidence, MutableConfidence> confidenceMap,
            List<String> validationErrors) {

        for (CryptoDetectorType dt : CryptoDetectorType.values()) {
            List<CryptoFinding> findings = detectorOutputs.getOrDefault(dt, List.of());
            MutableCounts detCounts = detectorCounts.get(dt);
            Map<CryptoConfidence, Integer> confDist = detectorConfDist.get(dt);

            for (CryptoFinding f : findings) {
                confDist.put(f.confidence(), confDist.getOrDefault(f.confidence(), 0) + 1);
            }

            if (sample.classification() == CryptoCorpusClassification.NEGATIVE_ADVERSARIAL) {
                // AN-003 Strict Differentiation Requirement:
                // Non-crypto fixtures (Base64, Deflate, CRC, LZ4, etc.) MUST NEVER be labeled encryption.
                boolean hadEncryption = false;
                for (CryptoFinding f : findings) {
                    if (f.isEncryption()) {
                        hadEncryption = true;
                        String err = String.format(Locale.ROOT,
                                "AN-003 violation: negative sample '%s' received isEncryption()==true from %s: %s",
                                sample.id(), dt.name(), f.algorithm().name());
                        validationErrors.add(err);
                        detCounts.fp++;
                        algorithmCounts.get(f.algorithm()).fp++;
                        confidenceMap.get(f.confidence()).total++;
                        confidenceMap.get(f.confidence()).fp++;
                    } else {
                        // Correctly differentiated non-encryption format (CRC, Base64, compression)
                        confidenceMap.get(f.confidence()).total++;
                        confidenceMap.get(f.confidence()).tp++;
                    }
                }
                if (!hadEncryption) {
                    detCounts.tn++;
                }

            } else if (sample.classification() == CryptoCorpusClassification.UNSUPPORTED_VARIANT) {
                // Unsupported case: verify detector did NOT hallucinate an unmodeled target algorithm
                CryptoAlgorithm targetAlgo = sample.unsupportedCase().targetAlgorithm();
                boolean falselyDetected = findings.stream().anyMatch(f -> f.algorithm() == targetAlgo);
                if (falselyDetected) {
                    detCounts.fp++;
                    algorithmCounts.get(targetAlgo).fp++;
                } else {
                    detCounts.tn++;
                }

            } else {
                // POSITIVE Sample
                boolean expectedDetector = sample.expectedDetectors().contains(dt);
                Set<CryptoAlgorithm> expectedAlgos = sample.expectedAlgorithms();
                Set<CryptoAlgorithm> detectedAlgos = new HashSet<>();

                for (CryptoFinding f : findings) {
                    detectedAlgos.add(f.algorithm());
                    if (expectedDetector && isExpectedAlgorithm(f.algorithm(), expectedAlgos, dt)) {
                        confidenceMap.get(f.confidence()).total++;
                        confidenceMap.get(f.confidence()).tp++;
                    } else {
                        confidenceMap.get(f.confidence()).total++;
                        confidenceMap.get(f.confidence()).fp++;
                    }
                }

                if (expectedDetector) {
                    boolean foundAnyExpected = false;
                    for (CryptoAlgorithm alg : detectedAlgos) {
                        if (isExpectedAlgorithm(alg, expectedAlgos, dt)) {
                            foundAnyExpected = true;
                            detCounts.tp++;
                            algorithmCounts.get(alg).tp++;
                        } else {
                            detCounts.fp++;
                            algorithmCounts.get(alg).fp++;
                        }
                    }
                    if (!foundAnyExpected) {
                        detCounts.fn++;
                        for (CryptoAlgorithm exp : expectedAlgos) {
                            algorithmCounts.get(exp).fn++;
                        }
                    }
                } else {
                    if (findings.isEmpty()) {
                        detCounts.tn++;
                    } else {
                        for (CryptoAlgorithm alg : detectedAlgos) {
                            detCounts.fp++;
                            algorithmCounts.get(alg).fp++;
                        }
                    }
                }
            }
        }
    }

    private static boolean isExpectedAlgorithm(
            CryptoAlgorithm algorithm,
            Set<CryptoAlgorithm> expectedAlgorithms,
            CryptoDetectorType detectorType) {
        if (expectedAlgorithms.contains(algorithm)) {
            return true;
        }
        if ((detectorType == CryptoDetectorType.KEY_MATERIAL || detectorType == CryptoDetectorType.FUSED_PIPELINE)
                && expectedAlgorithms.contains(CryptoAlgorithm.GENERIC_KEY)) {
            return algorithm == CryptoAlgorithm.AES_128
                    || algorithm == CryptoAlgorithm.AES_192
                    || algorithm == CryptoAlgorithm.AES_256
                    || algorithm == CryptoAlgorithm.GENERIC_KEY;
        }
        return false;
    }

    private static final class MutableCounts {
        int tp = 0;

        int fp = 0;

        int tn = 0;

        int fn = 0;
    }

    private static final class MutableConfidence {
        int total = 0;

        int tp = 0;

        int fp = 0;
    }
}
