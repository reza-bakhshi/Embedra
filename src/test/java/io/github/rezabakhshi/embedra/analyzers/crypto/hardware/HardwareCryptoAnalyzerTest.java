package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.List;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

class HardwareCryptoAnalyzerTest {

    private final HardwareCryptoAnalyzer analyzer = new HardwareCryptoAnalyzer();

    @Test
    void detectsEsp32S3HardwareAesTriggerAndBlockMode() throws Exception {
        List<HardwareMemoryAccess> accesses = List.of(
                HardwareMemoryAccess.write(0x42000000L, 0x6003_a040L, 0L), // AES-128
                HardwareMemoryAccess.write(0x42000008L, 0x6003_a064L, 1L), // CBC
                HardwareMemoryAccess.write(0x42000010L, 0x6003_a048L, 1L)  // Trigger
        );

        HardwareCryptoReport report = analyzer.analyze(
                HardwareCryptoPlatform.ESP32_S3,
                accesses,
                List.of(),
                List.of(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertFalse(report.findings().isEmpty());
        CryptoFinding finding = report.findings().get(0);
        assertEquals(0x42000010L, finding.address());
        assertEquals(CryptoAlgorithm.AES_128, finding.algorithm());
        assertEquals(CryptoConfidence.CONFIRMED, finding.confidence());
        assertTrue(finding.evidenceLayers().contains(CryptoEvidenceLayer.HARDWARE_PERIPHERAL));
        assertTrue(finding.evidenceLayers().contains(CryptoEvidenceLayer.DATA_FLOW));
        assertTrue(finding.explanation().contains("TRIGGER_CALCULATION"));
    }

    @Test
    void detectsStm32HardwareCrypAndHashTriggers() throws Exception {
        List<HardwareMemoryAccess> accesses = List.of(
                HardwareMemoryAccess.write(0x08001000L, 0x5006_0000L, 0x10L), // CRYP CR AES-ECB
                HardwareMemoryAccess.write(0x08001020L, 0x5006_0400L, 0x60L)  // HASH CR SHA-256
        );

        HardwareCryptoReport report = analyzer.analyze(
                HardwareCryptoPlatform.STM32_F4,
                accesses,
                List.of(),
                List.of(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(2, report.findings().size());
        CryptoFinding cryp = report.findings().get(0);
        assertEquals(CryptoAlgorithm.AES_128, cryp.algorithm());
        assertTrue(cryp.explanation().contains("AES-ECB"));

        CryptoFinding hash = report.findings().get(1);
        assertEquals(CryptoAlgorithm.SHA256, hash.algorithm());
        assertTrue(hash.explanation().contains("SHA-256"));
    }

    @Test
    void detectsVendorRomCallsAndRp2040LookupCodes() throws Exception {
        List<HardwareCallSite> callSites = List.of(
                new HardwareCallSite(0x10000100L, 0x40000720L, "ets_sha256_process", List.of()),
                new HardwareCallSite(0x10000200L, 0x00000010L, "rom_table_lookup", List.of((long) ('R' | ('E' << 8))))
        );

        HardwareCryptoReport report = analyzer.analyze(
                HardwareCryptoPlatform.GENERIC,
                List.of(),
                callSites,
                List.of(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(2, report.findings().size());
        CryptoFinding f1 = report.findings().get(0);
        assertEquals(CryptoAlgorithm.SHA256, f1.algorithm());
        assertTrue(f1.evidenceLayers().contains(CryptoEvidenceLayer.ROM_API));

        CryptoFinding f2 = report.findings().get(1);
        assertEquals(CryptoAlgorithm.FLASH_ENCRYPTION, f2.algorithm());
        assertTrue(f2.explanation().contains("flash_range_erase"));
    }

    @Test
    void detectsHardwareSecureElementCalls() throws Exception {
        List<HardwareCallSite> callSites = List.of(
                new HardwareCallSite(0x20000000L, 0x20001000L, "atecc608_init", List.of())
        );

        HardwareCryptoReport report = analyzer.analyze(
                HardwareCryptoPlatform.GENERIC,
                List.of(),
                callSites,
                List.of(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(1, report.findings().size());
        CryptoFinding se = report.findings().get(0);
        assertEquals(CryptoAlgorithm.SECURE_ELEMENT, se.algorithm());
        assertEquals(CryptoCategory.HARDWARE_SECURITY, se.category());
        assertTrue(se.explanation().contains("ATECC608A"));
    }

    @Test
    void detectsCrossProgramCryptoReferences() throws Exception {
        List<CrossProgramCryptoReference> refs = List.of(
                new CrossProgramCryptoReference("cross-core-key-handoff", "core0", "core1",
                        0x20040000L, 32, "KEY_BLOB_HANDOFF", true)
        );

        HardwareCryptoReport report = analyzer.analyze(
                HardwareCryptoPlatform.GENERIC,
                List.of(),
                List.of(),
                refs,
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(1, report.findings().size());
        CryptoFinding ref = report.findings().get(0);
        assertEquals(CryptoAlgorithm.EFUSE_KEY_LADDER, ref.algorithm());
        assertEquals(CryptoConfidence.CONFIRMED, ref.confidence());
        assertTrue(ref.evidenceLayers().contains(CryptoEvidenceLayer.HARDWARE_CONFIG));
    }
}
