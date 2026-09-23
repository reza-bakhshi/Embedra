package io.github.rezabakhshi.embedra.analyzers.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.formats.esp.EspAppDescription;
import io.github.rezabakhshi.embedra.pack.PackFile;
import io.github.rezabakhshi.embedra.pack.PackIntegrity;
import io.github.rezabakhshi.embedra.pack.PackManifest;
import io.github.rezabakhshi.embedra.pack.PackProvenance;
import io.github.rezabakhshi.embedra.pack.PackVersion;
import io.github.rezabakhshi.embedra.pack.RedistributionStatus;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class EspIdfEnrichmentAnalyzerTest {
    @Test
    void distinguishesMetadataLogUseSitesFreeRtosAndExactLibraryMatches()
            throws Exception {
        EspAnalysisContext context = context("esp-idf-v6.0", "esp-15.2.0_20251204",
            "Og", Optional.of(description("esp-idf-v6.0")),
            List.of(
                new EspStringFact(0x3c01_0100L, "wifi", new SourceRange(0x100, 5)),
                new EspStringFact(0x3c01_0120L, "connected: %d", new SourceRange(0x120, 14)),
                new EspStringFact(0x3c01_0140L, "xTaskCreate", new SourceRange(0x140, 12))),
            List.of(
                new EspSymbolFact("esp_log_write", 0x4000_1000L,
                    EspSymbolFactKind.FUNCTION, "espressif.esp32s3.rom@1.0.0"),
                new EspSymbolFact("xTaskCreate", 0x4037_9000L,
                    EspSymbolFactKind.FUNCTION, "esp-idf-v6.0-signatures@1.0.0"),
                new EspSymbolFact("pxCurrentTCB", 0x3fc8_9000L,
                    EspSymbolFactKind.DATA, "esp-idf-v6.0-signatures@1.0.0")),
            List.of(new EspCallFact(0x4037_8010L, 0x4037_8000L, 0x4000_1000L,
                List.of(3L, 0x3c01_0100L, 0x3c01_0120L))),
            List.of(new EspFunctionFact(0x4037_9000L,
                signatureBytes((byte) 0x44))));

        EspIdfEnrichmentReport report = new EspIdfEnrichmentAnalyzer().analyze(
            context, signaturePack("esp-idf-v6.0", "esp-15.2.0_20251204", "Og"),
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals("esp-idf-v6.0", report.idfMetadata().idfVersion().orElseThrow());
        assertEquals(Confidence.DERIVED, report.idfMetadata().confidence());
        assertEquals(1, report.loggingCalls().size());
        EspLoggingCall logging = report.loggingCalls().get(0);
        assertEquals("esp_log_write", logging.targetName());
        assertEquals("wifi", logging.tag().orElseThrow());
        assertEquals("connected: %d", logging.format().orElseThrow());
        assertEquals(0x4037_8010L, logging.callAddress());
        assertEquals(2, report.freeRtosEvidence().size());
        assertEquals(List.of("pxCurrentTCB", "xTaskCreate"),
            report.freeRtosEvidence().stream().map(EspFreeRtosEvidence::name).toList());
        assertEquals(1, report.libraryMatches().size());
        EspLibraryMatch match = report.libraryMatches().get(0);
        assertEquals("freertos.xTaskCreate.og", match.signatureId());
        assertEquals(Confidence.VERIFIED, match.confidence());
        assertEquals("esp-idf-v6.0-signatures@1.0.0", match.packIdentity());
        assertEquals(List.of("esp-idf-metadata", "esp-library-signatures",
            "esp-logging-calls", "freertos-symbols"), report.detectorsRun());
        assertTrue(report.unsupportedCapabilities().contains("freertos-heap-objects"));
        assertThrows(UnsupportedOperationException.class,
            () -> report.loggingCalls().clear());
    }

    @Test
    void stringsAndNearSignaturesAloneDoNotCreateVerifiedFindings() throws Exception {
        EspAnalysisContext context = context("esp-idf-v6.0", "esp-15.2.0_20251204",
            "Og", Optional.empty(),
            List.of(
                new EspStringFact(0x3c01_0100L, "ESP_LOGI", new SourceRange(0x100, 9)),
                new EspStringFact(0x3c01_0120L, "xTaskCreate", new SourceRange(0x120, 12))),
            List.of(), List.of(),
            List.of(new EspFunctionFact(0x4037_9000L,
                signatureBytes((byte) 0x45))));

        EspIdfEnrichmentReport report = new EspIdfEnrichmentAnalyzer().analyze(
            context, signaturePack("esp-idf-v6.0", "esp-15.2.0_20251204", "Og"),
            ParserLimits.defaults(), CancellationToken.none());

        assertTrue(report.idfMetadata().idfVersion().isEmpty());
        assertEquals(Confidence.UNKNOWN, report.idfMetadata().confidence());
        assertTrue(report.loggingCalls().isEmpty());
        assertTrue(report.freeRtosEvidence().isEmpty());
        assertTrue(report.libraryMatches().isEmpty());
    }

    @Test
    void signatureIndexMustMatchTargetIdfToolchainAndOptimization() throws Exception {
        EspAnalysisContext context = context("esp-idf-v6.0", "esp-15.2.0_20251204",
            "O2", Optional.of(description("esp-idf-v6.0")), List.of(), List.of(),
            List.of(), List.of(new EspFunctionFact(0x4037_9000L,
                signatureBytes((byte) 0x44))));

        EspIdfEnrichmentReport report = new EspIdfEnrichmentAnalyzer().analyze(
            context, signaturePack("esp-idf-v6.0", "esp-15.2.0_20251204", "Og"),
            ParserLimits.defaults(), CancellationToken.none());

        assertTrue(report.libraryMatches().isEmpty());
        assertTrue(report.unsupportedCapabilities().contains(
            "signature-index:esp32s3/esp-idf-v6.0/esp-15.2.0_20251204/O2"));
    }

    @Test
    void enforcesObjectAndByteLimitsCancellationAndModelImmutability() throws Exception {
        EspAnalysisContext context = context("esp-idf-v6.0", "toolchain", "Og",
            Optional.empty(), List.of(), List.of(), List.of(),
            List.of(new EspFunctionFact(0x4037_9000L, new byte[32])));
        ParserLimits tinyBytes = new ParserLimits(16, 16, 16, 100, 8,
            Duration.ofSeconds(30));
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> new EspIdfEnrichmentAnalyzer().analyze(context,
                signaturePack("esp-idf-v6.0", "toolchain", "Og"), tinyBytes,
                CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());

        ParserLimits tinyObjects = new ParserLimits(1024, 1024, 1024, 1, 8,
            Duration.ofSeconds(30));
        DiagnosticException tooManyObjects = assertThrows(DiagnosticException.class,
            () -> new EspIdfEnrichmentAnalyzer().analyze(context,
                signaturePack("esp-idf-v6.0", "toolchain", "Og"), tinyObjects,
                CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED,
            tooManyObjects.diagnostic().code());

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> new EspIdfEnrichmentAnalyzer().analyze(context,
                signaturePack("esp-idf-v6.0", "toolchain", "Og"),
                ParserLimits.defaults(), cancellation.token()));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());

        byte[] bytes = {1, 2, 3, 4};
        EspFunctionFact fact = new EspFunctionFact(0x4037_9000L, bytes);
        bytes[0] = 9;
        assertEquals(1, fact.bytes()[0]);
        byte[] returned = fact.bytes();
        returned[0] = 8;
        assertEquals(1, fact.bytes()[0]);
        assertFalse(context.strings().getClass().getName().isBlank());
        assertThrows(UnsupportedOperationException.class,
            () -> context.functions().clear());
    }

    private static EspAnalysisContext context(String idfVersion, String toolchain,
            String optimization, Optional<EspAppDescription> description,
            List<EspStringFact> strings, List<EspSymbolFact> symbols,
            List<EspCallFact> calls, List<EspFunctionFact> functions) {
        return new EspAnalysisContext("esp32s3", idfVersion, toolchain, optimization,
            description, strings, symbols, calls, functions);
    }

    private static EspAppDescription description(String idfVersion) {
        return new EspAppDescription(0xabcd5432L, 0, "1.0", "t023", "12:00:00",
            "Sep 23 2026", idfVersion, new byte[32], 0, 255, 0x10000,
            0x3c01_0020L, new SourceRange(0x20, 256));
    }

    private static EspIdfSignaturePack signaturePack(String idfVersion,
            String toolchain, String optimization) throws Exception {
        PackFile file = new PackFile("signatures.json", 4,
            "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a");
        PackManifest manifest = new PackManifest(PackManifest.SCHEMA_ID,
            "esp-idf-v6.0-signatures", PackVersion.parse("1.0.0"),
            PackIntegrity.contentDigest(List.of(file)), List.of("esp32s3"),
            new PackProvenance(new URI("https://example.invalid/test-owned"), "test-v1",
                "CC0-1.0", "Test-owned four-byte signature",
                RedistributionStatus.ALLOWED), List.of(file));
        EspLibrarySignature signature = new EspLibrarySignature(
            "freertos.xTaskCreate.og", "freertos", "xTaskCreate", "esp32s3",
            idfVersion, toolchain, optimization,
            signatureBytes((byte) 0x44),
            new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
        return new EspIdfSignaturePack(manifest, List.of(signature));
    }

    private static byte[] signatureBytes(byte finalByte) {
        return new byte[] {0x11, 0x22, 0x33, finalByte, 0x55, 0x66, 0x77,
            (byte) 0x88};
    }
}
