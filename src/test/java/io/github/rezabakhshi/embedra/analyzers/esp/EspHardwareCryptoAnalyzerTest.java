package io.github.rezabakhshi.embedra.analyzers.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import java.util.List;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

class EspHardwareCryptoAnalyzerTest {
    @Test
    void requiresConfigurationAndTriggerBeforeReportingResolvedHardwareAes() throws Exception {
        EspHardwareCryptoReport report = new EspHardwareCryptoAnalyzer().analyze(List.of(
            write(0x4200_1000L, 0x6003_a040L, 2),
            write(0x4200_1004L, 0x6003_a064L, 1),
            write(0x4200_1008L, 0x6003_a048L, 1)), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals(List.of("esp32s3-aes-mmio", "esp32s3-ds-mmio",
            "esp32s3-hmac-mmio", "esp32s3-rsa-mmio", "esp32s3-sha-mmio",
            "esp32s3-xts-aes-mmio"), report.detectorsRan());
        assertEquals(1, report.findings().size());
        EspHardwareCryptoFinding finding = report.findings().get(0);
        assertEquals("AES-256-CBC", finding.algorithm());
        assertEquals(EspCryptoEvidenceKind.HARDWARE_ACCELERATOR_USE, finding.kind());
        assertEquals(Confidence.DERIVED, finding.confidence());
        assertFalse(finding.evidence().isEmpty());
    }

    @Test
    void peripheralAddressOrConstantAloneDoesNotClaimCryptoUse() throws Exception {
        EspHardwareCryptoReport report = new EspHardwareCryptoAnalyzer().analyze(List.of(
            read(0x4200_2000L, 0x6003_a044L),
            writeUnknown(0x4200_2004L, 0x6003_a048L)), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals(List.of(), report.findings());
        assertFalse(report.unsupportedAlgorithms().isEmpty());
    }

    @Test
    void distinguishesHardwareHashAndRomApiUseSites() throws Exception {
        List<EspMemoryAccessFact> accesses = List.of(
            write(0x4200_3000L, 0x6003_b000L, 2),
            write(0x4200_3004L, 0x6003_b010L, 1));
        List<EspCryptoCallFact> calls = List.of(
            new EspCryptoCallFact(0x4200_4000L, 0x4000_1234L,
                "esp_sha256_start", "espressif.esp32s3.rom@1.0.0"));

        EspHardwareCryptoReport report = new EspHardwareCryptoAnalyzer().analyze(
            accesses, calls, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(2, report.findings().size());
        assertEquals(EspCryptoEvidenceKind.HARDWARE_ACCELERATOR_USE,
            report.findings().get(0).kind());
        assertEquals(EspCryptoEvidenceKind.ROM_API_CALLER,
            report.findings().get(1).kind());
    }

    private static EspMemoryAccessFact write(long instruction, long target, long value) {
        return new EspMemoryAccessFact(instruction, target, EspMemoryAccessKind.WRITE,
            OptionalLong.of(value));
    }

    private static EspMemoryAccessFact writeUnknown(long instruction, long target) {
        return new EspMemoryAccessFact(instruction, target, EspMemoryAccessKind.WRITE,
            OptionalLong.empty());
    }

    private static EspMemoryAccessFact read(long instruction, long target) {
        return new EspMemoryAccessFact(instruction, target, EspMemoryAccessKind.READ,
            OptionalLong.empty());
    }
}
