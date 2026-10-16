package io.github.rezabakhshi.embedra.analyzers.crypto.dataflow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for InterproceduralTaintAnalyzer (AN-010, AN-013, AN-014).
 */
class InterproceduralTaintAnalyzerTest {

    private InterproceduralTaintAnalyzer analyzer;

    private ParserLimits limits;

    @BeforeEach
    void setUp() {
        analyzer = new InterproceduralTaintAnalyzer();
        limits = ParserLimits.defaults();
    }

    @Test
    void directTaintPropagationWithinSingleFunction() throws Exception {
        TaintSource source = new TaintSource(
                "SRC_1", 0x1000L, TaintSource.TaintSourceKind.EFUSE_OTP_READ, "main");
        TaintSink sink = new TaintSink(
                "SINK_1", 0x2000L, TaintSink.TaintSinkKind.HARDWARE_MMIO_WRITE, "main");

        InterproceduralTaintReport report = analyzer.analyze(
                List.of(source),
                List.of(sink),
                List.of(),
                limits,
                CancellationToken.none()
        );

        assertNotNull(report);
        assertEquals(1, report.verifiedPaths().size());
        assertEquals(1, report.correlatedFindings().size());

        TaintPropagationPath path = report.verifiedPaths().get(0);
        assertEquals(source, path.source());
        assertEquals(sink, path.sink());
        assertEquals(0, path.depth());
        assertFalse(path.isSanitized());

        CryptoFinding finding = report.correlatedFindings().get(0);
        assertEquals(CryptoConfidence.CONFIRMED, finding.confidence());
        assertTrue(finding.evidenceLayers().contains(CryptoEvidenceLayer.DATA_FLOW));
        assertEquals("[REDACTED_SECRET]", finding.rawValue());
    }

    @Test
    void multiHopInterproceduralTaintPropagation() throws Exception {
        TaintSource source = new TaintSource(
                "SRC_KEY", 0x08001000L, TaintSource.TaintSourceKind.NVS_KEY_STORE, "load_credentials");
        TaintSink sink = new TaintSink(
                "SINK_AES", 0x08003000L, TaintSink.TaintSinkKind.CRYPTO_API_CALL, "aes_encrypt_block");

        // call chain: load_credentials -> prepare_session -> aes_encrypt_block
        InterproceduralCallEdge edge1 = new InterproceduralCallEdge(
                0x08001000L, "load_credentials", 0x08001050L, 0x08002000L, "prepare_session", 0, "session_key");
        InterproceduralCallEdge edge2 = new InterproceduralCallEdge(
                0x08002000L, "prepare_session", 0x08002040L, 0x08003000L, "aes_encrypt_block", 1, "raw_key");

        InterproceduralTaintReport report = analyzer.analyze(
                List.of(source),
                List.of(sink),
                List.of(edge1, edge2),
                limits,
                CancellationToken.none()
        );

        assertNotNull(report);
        assertEquals(1, report.verifiedPaths().size());
        TaintPropagationPath path = report.verifiedPaths().get(0);
        assertEquals(2, path.depth());
        assertEquals(2, path.steps().size());
        assertFalse(path.isSanitized());

        assertTrue(report.taintedFunctions().contains("load_credentials"));
        assertTrue(report.taintedFunctions().contains("prepare_session"));
        assertTrue(report.taintedFunctions().contains("aes_encrypt_block"));

        CryptoFinding finding = report.correlatedFindings().get(0);
        assertEquals(CryptoAlgorithm.AES_256, finding.algorithm());
        assertEquals(CryptoConfidence.CONFIRMED, finding.confidence());
    }

    @Test
    void sanitizedPathLowersConfidenceToPlausible() throws Exception {
        TaintSource source = new TaintSource(
                "SRC_2", 0x1000L, TaintSource.TaintSourceKind.HIGH_ENTROPY_KEY_CANDIDATE, "init");
        TaintSink sink = new TaintSink(
                "SINK_2", 0x3000L, TaintSink.TaintSinkKind.HARDWARE_MMIO_WRITE, "driver_write");

        InterproceduralCallEdge edge1 = new InterproceduralCallEdge(
                0x1000L, "init", 0x1020L, 0x2000L, "sanitize_explicit_bzero", 0, "key_buf");
        InterproceduralCallEdge edge2 = new InterproceduralCallEdge(
                0x2000L, "sanitize_explicit_bzero", 0x2040L, 0x3000L, "driver_write", 0, "key_buf");

        InterproceduralTaintReport report = analyzer.analyze(
                List.of(source),
                List.of(sink),
                List.of(edge1, edge2),
                limits,
                CancellationToken.none()
        );

        assertNotNull(report);
        assertEquals(1, report.verifiedPaths().size());
        TaintPropagationPath path = report.verifiedPaths().get(0);
        assertTrue(path.isSanitized());

        CryptoFinding finding = report.correlatedFindings().get(0);
        assertEquals(CryptoConfidence.PLAUSIBLE, finding.confidence());
    }

    @Test
    void cancellationTokenImmediatelyAborts() {
        CancellationToken token = () -> true;

        TaintSource source = new TaintSource("SRC", 0x1000L, TaintSource.TaintSourceKind.CONSTANT_TABLE, "f");
        assertThrows(DiagnosticException.class, () -> analyzer.analyze(
                List.of(source), List.of(), List.of(), limits, token));
    }

    @Test
    void resourceLimitExceededThrowsDiagnostic() {
        ParserLimits lowLimits = new ParserLimits(1024, 1024, 1024, 1, 10, Duration.ofSeconds(1));
        TaintSource s1 = new TaintSource("S1", 0x1000L, TaintSource.TaintSourceKind.CONSTANT_TABLE, "f1");
        TaintSource s2 = new TaintSource("S2", 0x2000L, TaintSource.TaintSourceKind.CONSTANT_TABLE, "f2");

        assertThrows(DiagnosticException.class, () -> analyzer.analyze(
                List.of(s1, s2), List.of(), List.of(), lowLimits, CancellationToken.none()));
    }
}
