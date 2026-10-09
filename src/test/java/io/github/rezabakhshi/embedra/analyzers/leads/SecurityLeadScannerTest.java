package io.github.rezabakhshi.embedra.analyzers.leads;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.leads.scanner.ComparisonLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.DebugCommandLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.DebugCommandLeadScanner.CommandTableEntry;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.OtaLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.SecurityLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class SecurityLeadScannerTest {

    @Test
    void unifiedScannerAggregatesAndRanksAcrossCategories() throws Exception {
        SecurityLeadScanner scanner = new SecurityLeadScanner();

        Map<Long, String> stringTable = Map.of(
                0x1000L, "super_secret_admin_pass",
                0x2000L, "shell> ",
                0x3000L, "https://ota.embedra.io/v2/firmware.bin");

        Map<Long, String> symbolMap = Map.of(
                0x4000L, "strcmp",
                0x5000L, "esp_console_init");

        List<CommandTableEntry> commandTables = List.of(
                new CommandTableEntry(0x6000L, "root", 0x7000L, "Root shell"));

        List<StackInstruction> funcInstrs = List.of(
                StackInstruction.arm(0x8000L, "ldr", "r0", "#0x1000"),
                StackInstruction.arm(0x8002L, "mov", "r1", "r4"),
                StackInstruction.arm(0x8004L, "bl", "0x4000"),
                StackInstruction.arm(0x8008L, "cbz", "r0", "0x8020"));

        Map<Long, List<StackInstruction>> functions = Map.of(0x8000L, funcInstrs);

        SecurityLeadsReport report = scanner.scanAll(
                functions,
                stringTable,
                symbolMap,
                commandTables,
                InstructionArch.ARM_THUMB,
                ParserLimits.defaults(),
                CancellationToken.none());

        assertTrue(report.totalCount() >= 4, "Should find comparison, branch, shell, OTA, and command leads");

        // Verify ranking order: higher confidence scores must appear first
        List<SecurityLead> ranked = report.rankedLeads();
        for (int i = 0; i < ranked.size() - 1; i++) {
            SecurityLead curr = ranked.get(i);
            SecurityLead next = ranked.get(i + 1);
            assertTrue(curr.confidenceScore() >= next.confidenceScore()
                    || (curr.confidenceScore() == next.confidenceScore()
                    && curr.severity().rank() >= next.severity().rank()),
                    "Leads must be sorted descending by confidence score and severity");
        }

        // Verify JSON export with secret masking
        String jsonMasked = report.toJson(true);
        assertTrue(jsonMasked.contains("\"totalLeads\":"), "JSON must have totalLeads");
        assertTrue(jsonMasked.contains("\"redacted\": true"));
        assertTrue(jsonMasked.contains("[REDACTED_SECRET]"), "Password string must be redacted");
        assertFalse(jsonMasked.contains("super_secret_admin_pass"), "Unmasked password must not leak");

        // Verify Markdown export with secret masking
        String mdMasked = report.toMarkdown(true);
        assertTrue(mdMasked.contains("# Candidate Security Leads (AN-005)"));
        assertTrue(mdMasked.contains("[REDACTED_SECRET]"));
        assertFalse(mdMasked.contains("super_secret_admin_pass"));

        // Verify SARIF export
        String sarif = report.toSarif(true);
        assertTrue(sarif.contains("sarif-2.1.0.json"));
        assertTrue(sarif.contains("EMBEDRA-LEAD-"));
    }

    @Test
    void respectsParserLimitsMaxObjects() throws Exception {
        SecurityLeadScanner scanner = new SecurityLeadScanner();

        Map<Long, String> stringTable = Map.of(
                0x1000L, "root",
                0x1010L, "admin",
                0x1020L, "debug",
                0x1030L, "backdoor",
                0x1040L, "reboot");

        ParserLimits tightLimits = new ParserLimits(
                65536, 65536, 65536, 2, 32, java.time.Duration.ofSeconds(10));

        SecurityLeadsReport report = scanner.scanAll(
                Map.of(),
                stringTable,
                Map.of(),
                List.of(),
                null,
                tightLimits,
                CancellationToken.none());

        assertTrue(report.totalCount() <= 2, "Lead count must not exceed maxObjects limit");
    }

    @Test
    void cooperativeCancellationThrowsDiagnosticException() {
        SecurityLeadScanner scanner = new SecurityLeadScanner();

        Map<Long, String> stringTable = Map.of(0x1000L, "factory_reset");
        AtomicBoolean cancelled = new AtomicBoolean(true);
        CancellationToken token = cancelled::get;

        assertThrows(DiagnosticException.class, () -> scanner.scanAll(
                Map.of(),
                stringTable,
                Map.of(),
                List.of(),
                null,
                ParserLimits.defaults(),
                token));
    }
}
