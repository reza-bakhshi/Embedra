package io.github.rezabakhshi.embedra.analyzers.findings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class UnifiedFindingsReportTest {

    @Test
    void reportSortsFindingsBySeverityAndScore() {
        UnifiedFinding f1 = new UnifiedFinding(
                "F1", FindingCategory.CRYPTOGRAPHY, "CRC", FindingSeverity.LOW, FindingConfidence.CONFIRMED,
                0.9, "ARM", 0x1000L, 4, "crc32", "CRC", false, false, null, Map.of());

        UnifiedFinding f2 = new UnifiedFinding(
                "F2", FindingCategory.SECURITY_LEAD, "PASSWORD", FindingSeverity.HIGH, FindingConfidence.CONFIRMED,
                0.9, "ARM", 0x2000L, 4, "secret_pw", "Password", true, false, null, Map.of());

        UnifiedFinding f3 = new UnifiedFinding(
                "F3", FindingCategory.SECURITY_LEAD, "OTA", FindingSeverity.HIGH, FindingConfidence.PLAUSIBLE,
                0.4, "ARM", 0x3000L, 4, "http://ota", "OTA", false, false, null, Map.of());

        UnifiedFindingsReport report = UnifiedFindingsReport.of("TestProgram", "ARM", List.of(f1, f2, f3));

        assertEquals(3, report.totalCount());
        assertEquals(3, report.activeCount());
        assertEquals(0, report.suppressedCount());

        List<UnifiedFinding> findings = report.rankedFindings();
        // High severity should be first
        assertEquals("F2", findings.get(0).id()); // High severity, score 0.9
        assertEquals("F3", findings.get(1).id()); // High severity, score 0.4
        assertEquals("F1", findings.get(2).id()); // Low severity, score 0.9
    }

    @Test
    void reportTracksSuppressedCounts() {
        UnifiedFinding f1 = new UnifiedFinding(
                "F1", FindingCategory.CRYPTOGRAPHY, "CRC", FindingSeverity.LOW, FindingConfidence.CONFIRMED,
                0.9, "ARM", 0x1000L, 4, "crc32", "CRC", false, true, "Not needed", Map.of());

        UnifiedFinding f2 = new UnifiedFinding(
                "F2", FindingCategory.SECURITY_LEAD, "PASSWORD", FindingSeverity.HIGH, FindingConfidence.CONFIRMED,
                0.9, "ARM", 0x2000L, 4, "secret_pw", "Password", true, false, null, Map.of());

        UnifiedFindingsReport report = UnifiedFindingsReport.of("TestProgram", "ARM", List.of(f1, f2));

        assertEquals(2, report.totalCount());
        assertEquals(1, report.activeCount());
        assertEquals(1, report.suppressedCount());
    }

    @Test
    void jsonExportRedactsSecretsByDefault() {
        UnifiedFinding secretFinding = new UnifiedFinding(
                "F1", FindingCategory.SECURITY_LEAD, "KEY", FindingSeverity.CRITICAL, FindingConfidence.CONFIRMED,
                0.99, "ARM", 0x1000L, 16, "super_private_token", "Auth token", true, false, null, Map.of());

        UnifiedFindingsReport report = UnifiedFindingsReport.of("TestProgram", "ARM", List.of(secretFinding));

        String jsonRedacted = report.toJson(true);
        assertTrue(jsonRedacted.contains("[REDACTED_SECRET]"));
        assertFalse(jsonRedacted.contains("super_private_token"));

        String jsonUnredacted = report.toJson(false);
        assertTrue(jsonUnredacted.contains("super_private_token"));
        assertFalse(jsonUnredacted.contains("[REDACTED_SECRET]"));
    }

    @Test
    void markdownExportRedactsSecretsByDefault() {
        UnifiedFinding secretFinding = new UnifiedFinding(
                "F1", FindingCategory.SECURITY_LEAD, "KEY", FindingSeverity.CRITICAL, FindingConfidence.CONFIRMED,
                0.99, "ARM", 0x1000L, 16, "super_private_token", "Auth token", true, false, null, Map.of());

        UnifiedFindingsReport report = UnifiedFindingsReport.of("TestProgram", "ARM", List.of(secretFinding));

        String mdRedacted = report.toMarkdown(true);
        assertTrue(mdRedacted.contains("[REDACTED_SECRET]"));
        assertFalse(mdRedacted.contains("super_private_token"));
        assertTrue(mdRedacted.contains("# Embedra Unified Security Findings Report"));

        String mdUnredacted = report.toMarkdown(false);
        assertTrue(mdUnredacted.contains("super_private_token"));
    }

    @Test
    void sarifExportProducesValidSarifStructure() {
        UnifiedFinding finding = new UnifiedFinding(
                "F1", FindingCategory.SECURITY_LEAD, "KEY", FindingSeverity.CRITICAL, FindingConfidence.CONFIRMED,
                0.99, "ARM", 0x1000L, 16, "token", "Auth token", false, false, null, Map.of());

        UnifiedFindingsReport report = UnifiedFindingsReport.of("TestProgram", "ARM", List.of(finding));

        String sarif = report.toSarif(true);
        assertNotNull(sarif);
        assertTrue(sarif.contains("\"version\": \"2.1.0\""));
        assertTrue(sarif.contains("\"name\": \"Embedra Static Analysis\""));
        assertTrue(sarif.contains("\"ruleId\": \"EMBEDRA-SECURITY_LEAD-KEY\""));
        assertTrue(sarif.contains("\"results\": ["));
    }
}
