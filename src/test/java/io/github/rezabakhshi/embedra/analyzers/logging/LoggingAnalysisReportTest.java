package io.github.rezabakhshi.embedra.analyzers.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class LoggingAnalysisReportTest {

    @Test
    void generatesJsonMarkdownAndSarifWithRedaction() {
        FormatStringDescriptor fmt = new FormatStringDescriptor(
                "User logged in with password: super_secret_password_123",
                List.of(), 0, List.of());

        LoggingCallSite site = new LoggingCallSite(
                0x08001000L,
                0x08000200L,
                "printf",
                DiagnosticLogLevel.INFO,
                fmt,
                Map.of("file", "auth.c", "line", "50"),
                "CONFIRMED",
                "User login logging"
        );

        LoggingAnalysisReport report = new LoggingAnalysisReport(List.of(site));
        assertEquals(1, report.totalCount());
        assertEquals(1, report.countByLevel().get(DiagnosticLogLevel.INFO));

        // Test JSON with redaction
        String jsonRedacted = report.toJson(true);
        assertTrue(jsonRedacted.contains("\"totalCallSites\": 1"));
        assertTrue(jsonRedacted.contains("***REDACTED***"));
        assertFalse(jsonRedacted.contains("super_secret_password_123"));

        // Test JSON without redaction
        String jsonUnredacted = report.toJson(false);
        assertTrue(jsonUnredacted.contains("super_secret_password_123"));

        // Test Markdown
        String md = report.toMarkdown(true);
        assertTrue(md.contains("Embedra Logging & Diagnostics Recovery Report"));
        assertTrue(md.contains("auth.c:50"));
        assertTrue(md.contains("***REDACTED***"));

        // Test SARIF
        String sarif = report.toSarif(true);
        assertTrue(sarif.contains("https://json.schemastore.org/sarif-2.1.0.json"));
        assertTrue(sarif.contains("EMBEDRA_LOG_INFO"));
        assertTrue(sarif.contains("***REDACTED***"));
    }
}
