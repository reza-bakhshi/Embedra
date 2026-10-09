package io.github.rezabakhshi.embedra.analyzers.findings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityCategory;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityType;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.HeuristicFactor;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadCategory;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadConfidence;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.logging.DiagnosticLogLevel;
import io.github.rezabakhshi.embedra.analyzers.logging.FormatStringDescriptor;
import io.github.rezabakhshi.embedra.analyzers.logging.LoggingCallSite;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class UnifiedFindingTest {

    @Test
    void secretRedactionMasksTargetProperly() {
        UnifiedFinding finding = new UnifiedFinding(
                "FND-001",
                FindingCategory.SECURITY_LEAD,
                "PASSWORD",
                FindingSeverity.HIGH,
                FindingConfidence.CONFIRMED,
                0.95,
                "ARM",
                0x1000L,
                16,
                "super_secret_admin_pass",
                "Password candidate",
                true,
                false,
                null,
                Map.of());

        assertEquals("[REDACTED_SECRET]", finding.maskedTarget(true));
        assertEquals("super_secret_admin_pass", finding.maskedTarget(false));
    }

    @Test
    void nonSecretTargetIsNotMasked() {
        UnifiedFinding finding = new UnifiedFinding(
                "FND-002",
                FindingCategory.LOGGING_DIAGNOSTIC,
                "INFO",
                FindingSeverity.INFO,
                FindingConfidence.CONFIRMED,
                0.90,
                "ARM",
                0x2000L,
                4,
                "Booting firmware...",
                "Boot message",
                false,
                false,
                null,
                Map.of());

        assertEquals("Booting firmware...", finding.maskedTarget(true));
        assertEquals("Booting firmware...", finding.maskedTarget(false));
    }

    @Test
    void withSuppressedCreatesModifiedCopy() {
        UnifiedFinding finding = new UnifiedFinding(
                "FND-003",
                FindingCategory.CTF_ENTITY,
                "FLAG",
                FindingSeverity.HIGH,
                FindingConfidence.CONFIRMED,
                0.90,
                "ARM",
                0x3000L,
                10,
                "FLAG{1234}",
                "Test flag",
                false,
                false,
                null,
                Map.of());

        assertFalse(finding.suppressed());
        UnifiedFinding suppressed = finding.withSuppressed(true, "Known false positive");
        assertTrue(suppressed.suppressed());
        assertEquals("Known false positive", suppressed.suppressionReason());

        UnifiedFinding unsuppressed = suppressed.withSuppressed(false, null);
        assertFalse(unsuppressed.suppressed());
    }

    @Test
    void fromCtfEntityConversion() {
        CtfEntity entity = new CtfEntity(
                "CTF-1",
                CtfEntityCategory.FLAG,
                CtfEntityType.FLAG,
                CtfSeverity.HIGH,
                StringConfidence.CONFIRMED,
                0x4000L,
                12,
                "CTF{success}",
                "Flag entity found",
                true,
                Map.of("entropy", "4.2"));

        UnifiedFinding f = FindingConverter.fromCtfEntity(entity, "ARM");
        assertEquals("CTF-1", f.id());
        assertEquals(FindingCategory.CTF_ENTITY, f.category());
        assertEquals(FindingSeverity.HIGH, f.severity());
        assertEquals(FindingConfidence.CONFIRMED, f.confidence());
        assertEquals(0x4000L, f.address());
        assertEquals("CTF{success}", f.target());
        assertTrue(f.secret());
        assertEquals("ARM", f.platform());
    }

    @Test
    void fromCryptoFindingConversion() {
        CryptoFinding cf = new CryptoFinding(
                "CRY-1",
                0x5000L,
                32,
                CryptoCategory.KEY_MATERIAL,
                CryptoAlgorithm.AES_256,
                CryptoConfidence.CONFIRMED,
                Set.of(CryptoEvidenceLayer.CONSTANT_TABLE),
                "AES-256 key schedule",
                "000102030405060708090a0b0c0d0e0f",
                true,
                Map.of("keySize", "256"));

        UnifiedFinding f = FindingConverter.fromCryptoFinding(cf, "ESP32");
        assertEquals("CRY-1", f.id());
        assertEquals(FindingCategory.CRYPTOGRAPHY, f.category());
        assertEquals(FindingSeverity.CRITICAL, f.severity());
        assertEquals(FindingConfidence.CONFIRMED, f.confidence());
        assertTrue(f.secret());
        assertEquals("ESP32", f.platform());
    }

    @Test
    void fromLoggingCallSiteConversion() {
        LoggingCallSite site = new LoggingCallSite(
                0x6000L,
                0x7000L,
                "esp_log_write",
                DiagnosticLogLevel.PANIC,
                FormatStringDescriptor.plain("Kernel panic at %s:%d"),
                Map.of("file", "main.c", "line", "42"),
                "CONFIRMED",
                "Recovered panic call");

        UnifiedFinding f = FindingConverter.fromLoggingCallSite(site, "Xtensa");
        assertEquals("LOG-00006000", f.id());
        assertEquals(FindingCategory.LOGGING_DIAGNOSTIC, f.category());
        assertEquals(FindingSeverity.CRITICAL, f.severity());
        assertEquals(FindingConfidence.CONFIRMED, f.confidence());
        assertEquals("esp_log_write", f.target());
        assertEquals("main.c", f.attributes().get("file"));
        assertEquals("42", f.attributes().get("line"));
    }

    @Test
    void fromSecurityLeadConversion() {
        SecurityLead lead = new SecurityLead(
                "LEAD-1",
                LeadCategory.PASSWORD_TOKEN_COMPARISON,
                LeadConfidence.HIGH,
                0.90,
                LeadSeverity.HIGH,
                0x8000L,
                "auth_check",
                "admin123",
                "Password comparison against static string",
                List.of(new HeuristicFactor("strcmp", "String comparison", 0.9)),
                Map.of(),
                true);

        UnifiedFinding f = FindingConverter.fromSecurityLead(lead, "RP2040");
        assertEquals("LEAD-1", f.id());
        assertEquals(FindingCategory.SECURITY_LEAD, f.category());
        assertEquals(FindingSeverity.HIGH, f.severity());
        assertEquals(FindingConfidence.CONFIRMED, f.confidence());
        assertEquals(0.90, f.confidenceScore());
        assertTrue(f.secret());
        assertEquals("RP2040", f.platform());
    }

    @Test
    void rejectsInvalidArguments() {
        assertThrows(NullPointerException.class, () ->
                new UnifiedFinding(null, FindingCategory.SECURITY_LEAD, "SUB", FindingSeverity.LOW,
                        FindingConfidence.LEAD, 0.1, "ARM", 0L, 4, "t", "e", false, false, null, Map.of()));

        assertThrows(IllegalArgumentException.class, () ->
                new UnifiedFinding("ID", FindingCategory.SECURITY_LEAD, "SUB", FindingSeverity.LOW,
                        FindingConfidence.LEAD, 0.1, "ARM", -1L, 4, "t", "e", false, false, null, Map.of()));
    }
}
