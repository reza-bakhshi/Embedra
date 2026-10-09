package io.github.rezabakhshi.embedra.analyzers.leads;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.leads.scanner.DebugCommandLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.DebugCommandLeadScanner.CommandTableEntry;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DebugCommandLeadScannerTest {

    @Test
    void detectsCommandTableEntriesWithHighRiskKeywords() throws Exception {
        DebugCommandLeadScanner scanner = new DebugCommandLeadScanner();

        List<CommandTableEntry> tableEntries = List.of(
                new CommandTableEntry(0x08040000L, "root", 0x08001000L, "Spawn root debug shell"),
                new CommandTableEntry(0x08040010L, "backdoor", 0x08001200L, "Engineering test mode"),
                new CommandTableEntry(0x08040020L, "status", 0x08001400L, "Display status"));

        Map<Long, String> stringTable = Map.of(
                0x08041000L, "root",
                0x08041010L, "backdoor",
                0x08041020L, "status");

        Map<Long, String> symbolMap = Map.of(
                0x08002000L, "esp_console_init");

        List<SecurityLead> leads = scanner.scan(
                stringTable,
                symbolMap,
                tableEntries,
                ParserLimits.defaults(),
                CancellationToken.none());

        // Both "root" and "backdoor" should be detected as high-confidence command leads
        List<SecurityLead> cmdLeads = leads.stream()
                .filter(l -> l.category() == LeadCategory.DEBUG_COMMAND)
                .toList();

        assertTrue(cmdLeads.size() >= 2);
        SecurityLead rootLead = cmdLeads.stream()
                .filter(l -> l.target().equals("root"))
                .findFirst()
                .orElseThrow();

        assertEquals(0x08040000L, rootLead.address());
        assertEquals(LeadConfidence.HIGH, rootLead.confidence());
        assertEquals(LeadSeverity.HIGH, rootLead.severity());
        assertEquals("0x8001000", rootLead.attributes().get("handlerAddress"));
    }

    @Test
    void detectsInteractiveDebugShellPromptCorroboratedBySymbol() throws Exception {
        DebugCommandLeadScanner scanner = new DebugCommandLeadScanner();

        Map<Long, String> stringTable = Map.of(
                0x2000L, "shell> ",
                0x2010L, "Device booting...");

        Map<Long, String> symbolMap = Map.of(
                0x5000L, "microrl_init");

        List<SecurityLead> leads = scanner.scan(
                stringTable,
                symbolMap,
                List.of(),
                ParserLimits.defaults(),
                CancellationToken.none());

        List<SecurityLead> shellLeads = leads.stream()
                .filter(l -> l.category() == LeadCategory.DEBUG_SHELL)
                .toList();

        assertEquals(1, shellLeads.size());
        SecurityLead shellLead = shellLeads.get(0);
        assertEquals(0x2000L, shellLead.address());
        assertEquals("shell> ", shellLead.target());
        assertEquals(LeadConfidence.HIGH, shellLead.confidence());
        assertTrue(shellLead.description().contains("microrl_init"));
        assertFalse(shellLead.secret());
    }

    @Test
    void detectsStandaloneDebugCommandKeyword() throws Exception {
        DebugCommandLeadScanner scanner = new DebugCommandLeadScanner();

        Map<Long, String> stringTable = Map.of(
                0x3000L, "factory_reset",
                0x3020L, "unrelated_sensor_data");

        Map<Long, String> symbolMap = Map.of();

        List<SecurityLead> leads = scanner.scan(
                stringTable,
                symbolMap,
                List.of(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(1, leads.size());
        SecurityLead lead = leads.get(0);
        assertEquals(LeadCategory.DEBUG_COMMAND, lead.category());
        assertEquals("factory_reset", lead.target());
    }
}
