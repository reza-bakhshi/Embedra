package io.github.rezabakhshi.embedra.analyzers.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.fusion.CryptoAnalysisPipeline;
import io.github.rezabakhshi.embedra.analyzers.crypto.fusion.CryptoAnalysisReport;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CryptoAnalysisPipelineTest {

    private CryptoAnalysisPipeline pipeline;

    private ParserLimits limits;

    private HexFormat hex;

    @BeforeEach
    void setUp() {
        pipeline = new CryptoAnalysisPipeline();
        limits = ParserLimits.defaults();
        hex = HexFormat.of();
    }

    @Test
    void promotesConfidenceWhenConstantCorrelatesWithStringLead() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("expand 32-byte k".getBytes(StandardCharsets.US_ASCII));
        byte[] data = out.toByteArray();

        // 1. Without string lead -> LIKELY
        CryptoAnalysisReport unassisted = pipeline.analyze(
                data, 0x1000L, CryptoScanOptions.defaults(), List.of(), List.of(), limits, CancellationToken.none());
        assertFalse(unassisted.findings().isEmpty());
        CryptoFinding f1 = unassisted.findings().get(0);
        assertEquals(CryptoConfidence.LIKELY, f1.confidence());
        assertEquals(1, f1.evidenceLayers().size());
        assertTrue(f1.evidenceLayers().contains(CryptoEvidenceLayer.CONSTANT_TABLE));

        // 2. With string lead ("chacha20_encrypt") -> CONFIRMED
        CryptoAnalysisReport assisted = pipeline.analyze(
                data, 0x1000L, CryptoScanOptions.defaults(),
                List.of("chacha20_init_block"), List.of(), limits, CancellationToken.none());
        CryptoFinding f2 = assisted.findings().get(0);
        assertEquals(CryptoConfidence.CONFIRMED, f2.confidence());
        assertTrue(f2.evidenceLayers().contains(CryptoEvidenceLayer.CONSTANT_TABLE));
        assertTrue(f2.evidenceLayers().contains(CryptoEvidenceLayer.SYMBOL_STRING));
    }

    @Test
    void enforcesStrictDifferentiationForCrcAndBase64() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz0123456789+/").getBytes(StandardCharsets.US_ASCII));

        byte[] data = out.toByteArray();
        CryptoAnalysisReport report = pipeline.analyze(data, 0x2000L, limits, CancellationToken.none());

        assertFalse(report.findings().isEmpty());
        for (CryptoFinding f : report.findings()) {
            assertFalse(f.isEncryption(), "Base64 must not be labeled encryption (AN-003)");
            assertEquals(CryptoCategory.ENCODING_OR_COMPRESSION, f.category());
        }
    }

    @Test
    void redactsSecretsInJsonMarkdownAndSarif() throws Exception {
        byte[] key16 = hex.parseHex("5a3b8c1d4e2f9076123456789abcdef0");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(key16);

        byte[] data = out.toByteArray();
        CryptoAnalysisReport report = pipeline.analyze(data, 0x3000L, limits, CancellationToken.none());

        assertFalse(report.findings().isEmpty());
        CryptoFinding keyFinding = report.findings().stream()
                .filter(f -> f.category() == CryptoCategory.KEY_MATERIAL)
                .findFirst()
                .orElseThrow();

        assertTrue(keyFinding.isSecret());
        String rawHex = keyFinding.rawValue();

        // 1. JSON export (default redacted = true)
        String json = report.toJson();
        assertFalse(json.contains(rawHex), "Raw secret key must never appear in default JSON export");
        assertTrue(json.contains(keyFinding.maskedValue()), "Masked value must appear in JSON");

        // 2. Markdown export (default redacted = true)
        String markdown = report.toMarkdown();
        assertFalse(markdown.contains(rawHex), "Raw secret key must never appear in default Markdown export");
        assertTrue(markdown.contains(keyFinding.maskedValue()), "Masked value must appear in Markdown");

        // 3. SARIF export (default redacted = true)
        String sarif = report.toSarif();
        assertFalse(sarif.contains(rawHex), "Raw secret key must never appear in default SARIF export");
        assertTrue(sarif.contains(keyFinding.maskedValue()), "Masked value must appear in SARIF");
    }

    @Test
    void respectsParserLimitsMaxObjects() throws Exception {
        ParserLimits tightLimits = new ParserLimits(
                1024 * 1024, 1024 * 1024, 1024 * 1024,
                1, 32, Duration.ofSeconds(30)); // max 1 object

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("expand 32-byte k".getBytes(StandardCharsets.US_ASCII));
        out.write("expand 16-byte k".getBytes(StandardCharsets.US_ASCII));

        byte[] data = out.toByteArray();
        CryptoAnalysisReport report = pipeline.analyze(data, 0x4000L, tightLimits, CancellationToken.none());
        assertTrue(report.totalCount() <= 1, "Must respect maxObjects limit");
    }

    @Test
    void honorsCooperativeCancellation() {
        byte[] data = new byte[1024];
        CancellationToken cancelled = () -> true;

        assertThrows(DiagnosticException.class, () ->
                pipeline.analyze(data, 0x5000L, limits, cancelled));
    }
}
