package io.github.rezabakhshi.embedra.analyzers.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.logging.linkage.CallSiteArgumentResolver;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CallSiteArgumentResolverTest {

    private CallSiteArgumentResolver resolver;

    private ParserLimits limits;

    @BeforeEach
    void setUp() {
        resolver = new CallSiteArgumentResolver();
        limits = ParserLimits.defaults();
    }

    @Test
    void resolvesArmThumbPrintfCallSite() throws Exception {
        Map<Long, String> strings = new HashMap<>();
        strings.put(0x08002000L, "System initialized: status=%d\n");

        List<StackInstruction> instructions = new ArrayList<>();
        // r0 = address of format string
        instructions.add(StackInstruction.arm(0x08001000L, "ldr", "r0", "0x08002000"));
        // r1 = 42
        instructions.add(StackInstruction.arm(0x08001002L, "movs", "r1", "#42"));
        // call printf
        instructions.add(StackInstruction.arm(0x08001004L, "bl", "printf"));

        List<LoggingCallSite> sites = resolver.resolveCallSites(
                0x08001000L, instructions, strings, limits, CancellationToken.none());

        assertEquals(1, sites.size());
        LoggingCallSite site = sites.get(0);
        assertEquals(0x08001004L, site.callInstructionAddress());
        assertEquals("printf", site.targetSymbol());
        assertEquals(DiagnosticLogLevel.INFO, site.level());
        assertNotNull(site.formatString());
        assertEquals("System initialized: status=%d\n", site.formatString().rawText());
        assertEquals(1, site.formatString().expectedArgumentCount());
        assertEquals("CONFIRMED", site.confidence());
    }

    @Test
    void resolvesArmThumbAssertCallSiteWithFileAndLine() throws Exception {
        Map<Long, String> strings = new HashMap<>();
        strings.put(0x08002050L, "main.c");
        strings.put(0x08002060L, "buf != NULL");

        List<StackInstruction> instructions = new ArrayList<>();
        // r0 = condition expression string
        instructions.add(StackInstruction.arm(0x08001010L, "ldr", "r0", "0x08002060"));
        // r1 = file name string
        instructions.add(StackInstruction.arm(0x08001012L, "ldr", "r1", "0x08002050"));
        // r2 = line number 142
        instructions.add(StackInstruction.arm(0x08001014L, "movs", "r2", "#142"));
        // bl __assert_func
        instructions.add(StackInstruction.arm(0x08001016L, "bl", "__assert_func"));
        // followed by bkpt trap
        instructions.add(StackInstruction.arm(0x08001018L, "bkpt", "#0"));

        List<LoggingCallSite> sites = resolver.resolveCallSites(
                0x08001000L, instructions, strings, limits, CancellationToken.none());

        assertEquals(1, sites.size());
        LoggingCallSite site = sites.get(0);
        assertEquals(DiagnosticLogLevel.ASSERT, site.level());
        assertEquals("main.c", site.fileName());
        assertEquals("142", site.lineNumber());
        assertEquals("buf != NULL", site.expression());
        assertEquals("CONFIRMED", site.confidence());
    }

    @Test
    void resolvesRiscVErrorLogCallSite() throws Exception {
        Map<Long, String> strings = new HashMap<>();
        strings.put(0x10002000L, "[E] Failed to connect Wi-Fi: error=%d\n");

        List<StackInstruction> instructions = new ArrayList<>();
        // a0 = format string
        instructions.add(StackInstruction.riscv(0x10001000L, "la", "a0", "0x10002000"));
        // a1 = -1
        instructions.add(StackInstruction.riscv(0x10001004L, "li", "a1", "-1"));
        // call log_write
        instructions.add(StackInstruction.riscv(0x10001008L, "call", "log_write"));

        List<LoggingCallSite> sites = resolver.resolveCallSites(
                0x10001000L, instructions, strings, limits, CancellationToken.none());

        assertEquals(1, sites.size());
        LoggingCallSite site = sites.get(0);
        assertEquals(DiagnosticLogLevel.ERROR, site.level());
        assertEquals("log_write", site.targetSymbol());
        assertEquals("[E] Failed to connect Wi-Fi: error=%d\n", site.formatString().rawText());
    }

    @Test
    void resolvesXtensaPanicCallSite() throws Exception {
        Map<Long, String> strings = new HashMap<>();
        strings.put(0x40082000L, "Fatal error: hardware watchdog timeout");

        List<StackInstruction> instructions = new ArrayList<>();
        // a2 = panic message string
        instructions.add(StackInstruction.xtensa(0x40081000L, "l32r", "a2", "0x40082000"));
        // call esp_system_abort
        instructions.add(StackInstruction.xtensa(0x40081003L, "call0", "esp_system_abort"));
        // break.n
        instructions.add(StackInstruction.xtensa(0x40081006L, "break.n", "1"));

        List<LoggingCallSite> sites = resolver.resolveCallSites(
                0x40081000L, instructions, strings, limits, CancellationToken.none());

        assertEquals(1, sites.size());
        LoggingCallSite site = sites.get(0);
        assertEquals(DiagnosticLogLevel.PANIC, site.level());
        assertEquals("Fatal error: hardware watchdog timeout", site.message());
    }

    @Test
    void respectsCancellation() {
        CancellationSource source = new CancellationSource();
        source.cancel();

        List<StackInstruction> instructions = List.of(
                StackInstruction.arm(0x08001000L, "bl", "printf")
        );

        assertThrows(DiagnosticException.class, () ->
                resolver.resolveCallSites(0x08001000L, instructions, Map.of(), limits, source.token()));
    }
}
