package io.github.rezabakhshi.embedra.analyzers.leads;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.leads.scanner.ComparisonLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ComparisonLeadScannerTest {

    @Test
    void detectsArmThumbPasswordComparisonAndAuthorizationBranch() throws Exception {
        ComparisonLeadScanner scanner = new ComparisonLeadScanner();

        // ARM Thumb disassembly:
        // 0x1000: ldr r0, =0x2000 (points to "admin_password")
        // 0x1002: mov r1, r4 (user input)
        // 0x1004: bl 0x3000 (strcmp)
        // 0x1008: cbz r0, 0x1020 (branch if match)
        List<StackInstruction> instructions = List.of(
                StackInstruction.arm(0x1000L, "ldr", "r0", "#0x2000"),
                StackInstruction.arm(0x1002L, "mov", "r1", "r4"),
                StackInstruction.arm(0x1004L, "bl", "0x3000"),
                StackInstruction.arm(0x1008L, "cbz", "r0", "0x1020"),
                StackInstruction.arm(0x100aL, "movs", "r0", "#1"),
                StackInstruction.arm(0x100cL, "bx", "lr"));

        Map<Long, String> stringTable = Map.of(0x2000L, "admin_password");
        Map<Long, String> symbolMap = Map.of(0x3000L, "strcmp");

        List<SecurityLead> leads = scanner.scanFunction(
                0x1000L,
                instructions,
                stringTable,
                symbolMap,
                InstructionArch.ARM_THUMB,
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(2, leads.size(), "Should discover password comparison and authorization branch leads");

        // 1. Password comparison lead
        SecurityLead cmpLead = leads.stream()
                .filter(l -> l.category() == LeadCategory.PASSWORD_TOKEN_COMPARISON)
                .findFirst()
                .orElseThrow();

        assertEquals(0x1004L, cmpLead.address());
        assertEquals("strcmp", cmpLead.symbol());
        assertEquals("admin_password", cmpLead.target());
        assertTrue(cmpLead.secret(), "Candidate password string should be flagged as secret");
        assertTrue(cmpLead.confidenceScore() >= 0.75, "Confidence score should be high");
        assertEquals(LeadConfidence.HIGH, cmpLead.confidence());
        assertEquals("[REDACTED_SECRET]", cmpLead.maskedTarget(true));

        // 2. Authorization branch lead
        SecurityLead authLead = leads.stream()
                .filter(l -> l.category() == LeadCategory.AUTHORIZATION_BRANCH)
                .findFirst()
                .orElseThrow();

        assertEquals(0x1008L, authLead.address());
        assertEquals("cbz", authLead.target());
        assertFalse(authLead.secret());
        assertEquals(LeadConfidence.HIGH, authLead.confidence());
        assertEquals("0x1020", authLead.attributes().get("targetTaken"));
    }

    @Test
    void detectsRiscVConstantTimeCryptoComparison() throws Exception {
        ComparisonLeadScanner scanner = new ComparisonLeadScanner();

        // RISC-V disassembly:
        // 0x2000: la a0, #0x4000 (points to "master_token")
        // 0x2004: mv a1, s1 (input buffer)
        // 0x2008: li a2, #32 (length)
        // 0x200c: call 0x5000 (CRYPTO_memcmp)
        // 0x2010: bnez a0, 0x2030 (branch if mismatch)
        List<StackInstruction> instructions = List.of(
                StackInstruction.riscv(0x2000L, "la", "a0", "#0x4000"),
                StackInstruction.riscv(0x2004L, "mv", "a1", "s1"),
                StackInstruction.riscv(0x2008L, "li", "a2", "#32"),
                StackInstruction.riscv(0x200cL, "call", "0x5000"),
                StackInstruction.riscv(0x2010L, "bnez", "a0", "0x2030"),
                StackInstruction.riscv(0x2014L, "ret"));

        Map<Long, String> stringTable = Map.of(0x4000L, "master_token");
        Map<Long, String> symbolMap = Map.of(0x5000L, "CRYPTO_memcmp");

        List<SecurityLead> leads = scanner.scanFunction(
                0x2000L,
                instructions,
                stringTable,
                symbolMap,
                InstructionArch.RISCV32,
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(2, leads.size());
        SecurityLead cmpLead = leads.get(0);
        assertEquals(LeadCategory.PASSWORD_TOKEN_COMPARISON, cmpLead.category());
        assertEquals("CRYPTO_memcmp", cmpLead.symbol());
        assertTrue(cmpLead.heuristicFactors().stream()
                .anyMatch(h -> h.factorId().equals("CONSTANT_TIME_COMPARE")));
        assertEquals(LeadSeverity.CRITICAL, cmpLead.severity());
    }

    @Test
    void detectsXtensaCustomVerifyPinFunction() throws Exception {
        ComparisonLeadScanner scanner = new ComparisonLeadScanner();

        // Xtensa disassembly:
        // 0x4000: movi a2, #0x6000 (points to "1234_pin")
        // 0x4003: mov a3, a8
        // 0x4006: call0 0x7000 (verify_pin)
        // 0x4009: beqz.n a2, 0x4020
        List<StackInstruction> instructions = List.of(
                StackInstruction.xtensa(0x4000L, "movi", "a2", "#0x6000"),
                StackInstruction.xtensa(0x4003L, "mov", "a3", "a8"),
                StackInstruction.xtensa(0x4006L, "call0", "0x7000"),
                StackInstruction.xtensa(0x4009L, "beqz.n", "a2", "0x4020"));

        Map<Long, String> stringTable = Map.of(0x6000L, "1234_pin");
        Map<Long, String> symbolMap = Map.of(0x7000L, "verify_pin");

        List<SecurityLead> leads = scanner.scanFunction(
                0x4000L,
                instructions,
                stringTable,
                symbolMap,
                InstructionArch.XTENSA,
                ParserLimits.defaults(),
                CancellationToken.none());

        assertFalse(leads.isEmpty());
        SecurityLead lead = leads.get(0);
        assertEquals(LeadCategory.PASSWORD_TOKEN_COMPARISON, lead.category());
        assertEquals("verify_pin", lead.symbol());
        assertTrue(lead.secret());
    }

    @Test
    void ignoresHarmlessNonSensitiveComparison() throws Exception {
        ComparisonLeadScanner scanner = new ComparisonLeadScanner();

        // Harmless strcmp checking file extension
        List<StackInstruction> instructions = List.of(
                StackInstruction.arm(0x1000L, "ldr", "r0", "#0x2000"),
                StackInstruction.arm(0x1002L, "mov", "r1", "r4"),
                StackInstruction.arm(0x1004L, "bl", "0x3000"),
                StackInstruction.arm(0x1008L, "bx", "lr"));

        Map<Long, String> stringTable = Map.of(0x2000L, ".txt");
        Map<Long, String> symbolMap = Map.of(0x3000L, "strcmp");

        List<SecurityLead> leads = scanner.scanFunction(
                0x1000L,
                instructions,
                stringTable,
                symbolMap,
                InstructionArch.ARM_THUMB,
                ParserLimits.defaults(),
                CancellationToken.none());

        assertTrue(leads.isEmpty(), "Non-sensitive strcmp with extension should not produce high-risk lead");
    }
}
