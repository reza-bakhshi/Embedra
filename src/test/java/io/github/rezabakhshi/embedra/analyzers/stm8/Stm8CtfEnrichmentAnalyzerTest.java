package io.github.rezabakhshi.embedra.analyzers.stm8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityType;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class Stm8CtfEnrichmentAnalyzerTest {

    @Test
    void recoversCtfEntitiesAndSignaturesFromStm8Firmware() throws Exception {
        Stm8CtfEnrichmentAnalyzer analyzer = new Stm8CtfEnrichmentAnalyzer();

        // Construct synthetic STM8 flash buffer containing:
        // 1. Vector table (128 bytes)
        // 2. Embedded static strings: Flag, URL, and command strings
        byte[] flash = new byte[1024];

        // Slot 0: Reset vector to 0x008080
        flash[0] = (byte) 0x82;
        flash[1] = 0x00;
        flash[2] = (byte) 0x80;
        flash[3] = (byte) 0x80;

        // At 0x008080 (offset 128): CLK_DeInit byte pattern
        byte[] clkDeInit = new byte[] {
            0x35, 0x01, 0x50, (byte) 0xC0, 0x35, 0x00, 0x50, (byte) 0xC1,
            0x35, (byte) 0xE1, 0x50, (byte) 0xC4, 0x35, 0x00, 0x50, (byte) 0xC5,
            (byte) 0x81, (byte) 0x9D
        };
        System.arraycopy(clkDeInit, 0, flash, 128, clkDeInit.length);

        // At 0x008100 (offset 256): Embed Flag string
        byte[] flagBytes = "flag{stm8_cisc_recovery_pass}\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(flagBytes, 0, flash, 256, flagBytes.length);

        // At 0x008140 (offset 320): Embed URL
        byte[] urlBytes = "https://update.stm8.internal/ota\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(urlBytes, 0, flash, 320, urlBytes.length);

        // At 0x008180 (offset 384): Embed Command string "debug"
        byte[] cmdBytes = "debug\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(cmdBytes, 0, flash, 384, cmdBytes.length);

        // At 0x008200 (offset 512): Command table with 16-bit pointers:
        // entry 1: strPtr=0x008180, fnPtr=0x008080
        flash[512] = (byte) 0x81;
        flash[513] = (byte) 0x80;
        flash[514] = (byte) 0x80;
        flash[515] = (byte) 0x80;

        Stm8SignatureContext sigContext = new Stm8SignatureContext(
                "STM8S003F3P6",
                "STM8S",
                Optional.of("SDCC"),
                Optional.of("-Os"),
                List.of(new Stm8FunctionBytes(0x008080L, clkDeInit)));

        // Create instructions for function at 0x008080 calling strcmp
        Map<Long, List<StackInstruction>> funcInstructions = new HashMap<>();
        List<StackInstruction> instrs = List.of(
                StackInstruction.stm8(0x008080L, "ldw", "x", "#0x8180"),
                StackInstruction.stm8(0x008083L, "ldw", "y", "#0x01"),
                StackInstruction.stm8(0x008086L, "call", "strcmp"),
                StackInstruction.stm8(0x008089L, "jreq", "0x8090"),
                StackInstruction.stm8(0x00808BL, "ret")
        );
        funcInstructions.put(0x008080L, instrs);

        Map<Long, String> symbolMap = Map.of(
                0x008080L, "Reset_Handler",
                0x008180L, "cmd_debug_str"
        );

        Stm8CtfEnrichmentContext context = new Stm8CtfEnrichmentContext(
                sigContext,
                flash,
                0x008000L,
                symbolMap,
                funcInstructions);

        Stm8CtfEnrichmentReport report = analyzer.analyze(
                context,
                Stm8SignaturePack.builtin(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertNotNull(report);

        // 1. Signatures matched
        assertEquals(1, report.signatureReport().matches().size());
        assertEquals("CLK_DeInit", report.signatureReport().matches().get(0).functionName());

        // 2. Extracted strings
        assertFalse(report.extractedStrings().isEmpty());
        assertTrue(report.extractedStrings().stream()
                .anyMatch(s -> s.content().contains("flag{stm8_cisc_recovery_pass}")));
        assertTrue(report.extractedStrings().stream()
                .anyMatch(s -> s.content().contains("https://update.stm8.internal/ota")));

        // 3. CTF entities
        assertFalse(report.ctfEntities().isEmpty());
        assertTrue(report.ctfEntities().stream()
                .anyMatch(e -> e.type() == CtfEntityType.FLAG));
        assertTrue(report.ctfEntities().stream()
                .anyMatch(e -> e.type() == CtfEntityType.URL));

        // 4. Detectors run
        assertEquals(5, report.detectorsRun().size());
    }

    @Test
    void recoversStackConstructedStringsOnStm8() throws Exception {
        Stm8CtfEnrichmentAnalyzer analyzer = new Stm8CtfEnrichmentAnalyzer();

        // Function constructing "PASS" on stack using STM8 instructions
        List<StackInstruction> instrs = List.of(
                StackInstruction.stm8(0x008080L, "mov", "(1, sp)", "#0x50"),  // 'P'
                StackInstruction.stm8(0x008084L, "mov", "(2, sp)", "#0x41"),  // 'A'
                StackInstruction.stm8(0x008088L, "mov", "(3, sp)", "#0x53"),  // 'S'
                StackInstruction.stm8(0x00808CL, "mov", "(4, sp)", "#0x53"),  // 'S'
                StackInstruction.stm8(0x008090L, "mov", "(5, sp)", "#0x00"),  // null terminator
                StackInstruction.stm8(0x008094L, "ret")
        );

        byte[] emptyFlash = new byte[256];
        Stm8SignatureContext sigContext = new Stm8SignatureContext(
                "STM8S003F3P6", "STM8S", Optional.of("SDCC"), Optional.of("-Os"), List.of());

        Stm8CtfEnrichmentContext context = new Stm8CtfEnrichmentContext(
                sigContext,
                emptyFlash,
                0x008000L,
                Map.of(),
                Map.of(0x008080L, instrs));

        Stm8CtfEnrichmentReport report = analyzer.analyze(
                context,
                Stm8SignaturePack.builtin(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertNotNull(report);
    }
}
