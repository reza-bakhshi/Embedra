package io.github.rezabakhshi.embedra.analyzers.strings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackStringRecoveryAnalyzer;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StackStringRecoveryAnalyzerTest {

    private StackStringRecoveryAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new StackStringRecoveryAnalyzer();
    }

    @Test
    void recoversArmThumbByteConstructedStackString() throws Exception {
        List<StackInstruction> instructions = new ArrayList<>();
        long funcAddr = 0x08001000L;
        long addr = funcAddr;

        String target = "FLAG{arm_thumb_recovered}\0";
        for (int i = 0; i < target.length(); i++) {
            char c = target.charAt(i);
            instructions.add(StackInstruction.arm(addr, "movs", "r0", String.format("#0x%02X", (int) c)));
            addr += 2;
            instructions.add(StackInstruction.arm(addr, "strb", "r0", String.format("[sp, #%d]", i)));
            addr += 2;
        }

        List<RecoveredStackString> recovered = analyzer.analyzeFunction(
                funcAddr, instructions, ParserLimits.defaults(), CancellationToken.none());

        assertFalse(recovered.isEmpty());
        RecoveredStackString str = recovered.get(0);
        assertEquals("FLAG{arm_thumb_recovered}", str.content());
        assertEquals(StringConfidence.CONFIRMED, str.confidence());
        assertEquals(funcAddr, str.functionAddress());
        assertEquals(0L, str.stackOffset());
        assertEquals(funcAddr + 2, str.startInstructionAddress());
        assertEquals(target.length(), str.instructionCount());

        ExtractedString extracted = str.toExtractedString();
        assertEquals(StringProvenance.STACK_CONSTRUCTED, extracted.provenance());
        assertEquals("FLA...d}", str.redactedContent());
    }

    @Test
    void recoversArmThumb2WordConstructedStackString() throws Exception {
        List<StackInstruction> instructions = new ArrayList<>();
        long funcAddr = 0x08002000L;
        long addr = funcAddr;

        // "FLAG" -> 0x47414C46
        instructions.add(StackInstruction.arm(addr, "movw", "r0", "#0x4C46"));
        addr += 4;
        instructions.add(StackInstruction.arm(addr, "movt", "r0", "#0x4741"));
        addr += 4;
        instructions.add(StackInstruction.arm(addr, "str", "r0", "[sp, #0]"));
        addr += 4;

        // "{ARM" -> 0x4D52417B
        instructions.add(StackInstruction.arm(addr, "movw", "r1", "#0x417B"));
        addr += 4;
        instructions.add(StackInstruction.arm(addr, "movt", "r1", "#0x4D52"));
        addr += 4;
        instructions.add(StackInstruction.arm(addr, "str", "r1", "[sp, #4]"));
        addr += 4;

        // "}\0\0\0" -> 0x0000007D
        instructions.add(StackInstruction.arm(addr, "movs", "r2", "#0x7D"));
        addr += 2;
        instructions.add(StackInstruction.arm(addr, "strb", "r2", "[sp, #8]"));
        addr += 2;
        instructions.add(StackInstruction.arm(addr, "movs", "r2", "#0x00"));
        addr += 2;
        instructions.add(StackInstruction.arm(addr, "strb", "r2", "[sp, #9]"));

        List<RecoveredStackString> recovered = analyzer.analyzeFunction(
                funcAddr, instructions, ParserLimits.defaults(), CancellationToken.none());

        assertFalse(recovered.isEmpty());
        RecoveredStackString str = recovered.get(0);
        assertEquals("FLAG{ARM}", str.content());
        assertEquals(StringConfidence.CONFIRMED, str.confidence());
        assertEquals(0L, str.stackOffset());
    }

    @Test
    void recoversArmThumbFramePointerStackString() throws Exception {
        List<StackInstruction> instructions = new ArrayList<>();
        long funcAddr = 0x08003000L;
        long addr = funcAddr;

        // Setup frame pointer r7 = sp + 16
        instructions.add(StackInstruction.arm(addr, "add", "r7", "sp", "#16"));
        addr += 2;

        String secret = "SecretFrameToken\0";
        for (int i = 0; i < secret.length(); i++) {
            instructions.add(StackInstruction.arm(addr, "movs", "r3", String.format("#%d", (int) secret.charAt(i))));
            addr += 2;
            instructions.add(StackInstruction.arm(addr, "strb", "r3", String.format("[r7, #%d]", i)));
            addr += 2;
        }

        List<RecoveredStackString> recovered = analyzer.analyzeFunction(
                funcAddr, instructions, ParserLimits.defaults(), CancellationToken.none());

        assertFalse(recovered.isEmpty());
        RecoveredStackString str = recovered.get(0);
        assertEquals("SecretFrameToken", str.content());
        assertEquals(16L, str.stackOffset());
    }

    @Test
    void recoversRiscv32StackString() throws Exception {
        List<StackInstruction> instructions = new ArrayList<>();
        long funcAddr = 0x20001000L;
        long addr = funcAddr;

        String riscvFlag = "FLAG{riscv32_hazard3}\0";
        for (int i = 0; i < riscvFlag.length(); i++) {
            char c = riscvFlag.charAt(i);
            if (c == 0) {
                instructions.add(StackInstruction.riscv(addr, "sb", "zero", String.format("%d(sp)", i)));
            } else {
                instructions.add(StackInstruction.riscv(addr, "li", "a0", String.format("0x%02X", (int) c)));
                addr += 4;
                instructions.add(StackInstruction.riscv(addr, "sb", "a0", String.format("%d(sp)", i)));
            }
            addr += 4;
        }

        List<RecoveredStackString> recovered = analyzer.analyzeFunction(
                funcAddr, instructions, ParserLimits.defaults(), CancellationToken.none());

        assertFalse(recovered.isEmpty());
        RecoveredStackString str = recovered.get(0);
        assertEquals("FLAG{riscv32_hazard3}", str.content());
        assertEquals(StringConfidence.CONFIRMED, str.confidence());
        assertEquals(0L, str.stackOffset());
    }

    @Test
    void recoversXtensaStackString() throws Exception {
        List<StackInstruction> instructions = new ArrayList<>();
        long funcAddr = 0x40001000L;
        long addr = funcAddr;

        String xtensaStr = "FLAG{xtensa_esp32}\0";
        for (int i = 0; i < xtensaStr.length(); i++) {
            char c = xtensaStr.charAt(i);
            instructions.add(StackInstruction.xtensa(addr, "movi", "a2", String.format("0x%02X", (int) c)));
            addr += 3;
            instructions.add(StackInstruction.xtensa(addr, "s8i", "a2", "a1", String.format("%d", i)));
            addr += 3;
        }

        List<RecoveredStackString> recovered = analyzer.analyzeFunction(
                funcAddr, instructions, ParserLimits.defaults(), CancellationToken.none());

        assertFalse(recovered.isEmpty());
        RecoveredStackString str = recovered.get(0);
        assertEquals("FLAG{xtensa_esp32}", str.content());
        assertEquals(StringConfidence.CONFIRMED, str.confidence());
        assertEquals(0L, str.stackOffset());
    }

    @Test
    void recoversMultipleStackStringsInSingleFunction() throws Exception {
        List<StackInstruction> instructions = new ArrayList<>();
        long funcAddr = 0x1000L;
        long addr = funcAddr;

        // String 1 at sp+0: "admin"
        String s1 = "admin\0";
        for (int i = 0; i < s1.length(); i++) {
            instructions.add(StackInstruction.arm(addr++, "movs", "r0", String.format("#%d", (int) s1.charAt(i))));
            instructions.add(StackInstruction.arm(addr++, "strb", "r0", String.format("[sp, #%d]", i)));
        }

        // String 2 at sp+32: "password"
        String s2 = "password\0";
        for (int i = 0; i < s2.length(); i++) {
            instructions.add(StackInstruction.arm(addr++, "movs", "r0", String.format("#%d", (int) s2.charAt(i))));
            instructions.add(StackInstruction.arm(addr++, "strb", "r0", String.format("[sp, #%d]", 32 + i)));
        }

        List<RecoveredStackString> recovered = analyzer.analyzeFunction(
                funcAddr, instructions, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(2, recovered.size());
        assertEquals("admin", recovered.get(0).content());
        assertEquals(0L, recovered.get(0).stackOffset());
        assertEquals("password", recovered.get(1).content());
        assertEquals(32L, recovered.get(1).stackOffset());
    }

    @Test
    void analyzesFunctionsAcrossMap() throws Exception {
        long f1 = 0x1000L;
        long f2 = 0x2000L;

        List<StackInstruction> i1 = List.of(
                StackInstruction.arm(f1, "movs", "r0", "#0x41"),
                StackInstruction.arm(f1 + 2, "strb", "r0", "[sp, #0]"),
                StackInstruction.arm(f1 + 4, "movs", "r0", "#0x42"),
                StackInstruction.arm(f1 + 6, "strb", "r0", "[sp, #1]"),
                StackInstruction.arm(f1 + 8, "movs", "r0", "#0x43"),
                StackInstruction.arm(f1 + 10, "strb", "r0", "[sp, #2]"),
                StackInstruction.arm(f1 + 12, "movs", "r0", "#0x44"),
                StackInstruction.arm(f1 + 14, "strb", "r0", "[sp, #3]"),
                StackInstruction.arm(f1 + 16, "movs", "r0", "#0x00"),
                StackInstruction.arm(f1 + 18, "strb", "r0", "[sp, #4]")
        );

        List<RecoveredStackString> result = analyzer.analyzeFunctions(
                Map.of(f1, i1), ParserLimits.defaults(), CancellationToken.none());
        assertEquals(1, result.size());
        assertEquals("ABCD", result.get(0).content());
    }

    @Test
    void enforcesCancellationAndLimits() {
        CancellationToken cancelled = () -> true;
        DiagnosticException ex = assertThrows(
                DiagnosticException.class,
                () -> analyzer.analyzeFunctions(Map.of(0x1000L, List.of()), ParserLimits.defaults(), cancelled));
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());

        ParserLimits tightLimits = new ParserLimits(1024, 1024, 1024, 1, 1, Duration.ofNanos(1));
        assertThrows(
                DiagnosticException.class,
                () -> {
                    List<StackInstruction> deep = new ArrayList<>();
                    for (int i = 0; i < 500; i++) {
                        deep.add(StackInstruction.arm(0x1000L + i * 2, "nop"));
                    }
                    analyzer.analyzeFunction(0x1000L, deep, tightLimits, CancellationToken.none());
                });
    }
}
