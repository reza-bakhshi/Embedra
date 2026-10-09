package io.github.rezabakhshi.embedra.analyzers.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.logging.scanner.AssertPanicPatternMatcher;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AssertPanicPatternMatcherTest {

    private AssertPanicPatternMatcher matcher;

    @BeforeEach
    void setUp() {
        matcher = new AssertPanicPatternMatcher();
    }

    @Test
    void identifiesKnownAssertAndPanicSymbols() {
        assertTrue(matcher.isPanicFunction("panic"));
        assertTrue(matcher.isPanicFunction("hard_assert"));
        assertTrue(matcher.isPanicFunction("esp_system_abort"));
        assertTrue(matcher.isPanicFunction("__abort"));

        assertTrue(matcher.isAssertFunction("assert"));
        assertTrue(matcher.isAssertFunction("__assert_func"));
        assertTrue(matcher.isAssertFunction("configASSERT"));
        assertTrue(matcher.isAssertFunction("assert_param"));

        assertFalse(matcher.isPanicFunction("printf"));
        assertFalse(matcher.isAssertFunction("memcpy"));
    }

    @Test
    void recognizesSourceFileNamesAndLineNumbers() {
        assertTrue(matcher.isSourceFileName("main.c"));
        assertTrue(matcher.isSourceFileName("src/driver/uart.cpp"));
        assertTrue(matcher.isSourceFileName("C:\\embedded\\kernel.h"));
        assertFalse(matcher.isSourceFileName("NotAFile"));
        assertFalse(matcher.isSourceFileName("config.json"));

        assertTrue(matcher.isLineNumber(42));
        assertTrue(matcher.isLineNumber(1));
        assertTrue(matcher.isLineNumber(499999));
        assertFalse(matcher.isLineNumber(0));
        assertFalse(matcher.isLineNumber(-10));
        assertFalse(matcher.isLineNumber(1000000));
    }

    @Test
    void recognizesConditionExpressions() {
        assertTrue(matcher.isConditionExpression("ptr != NULL"));
        assertTrue(matcher.isConditionExpression("count > 0"));
        assertTrue(matcher.isConditionExpression("x == 0"));
        assertTrue(matcher.isConditionExpression("!is_ready"));
        assertFalse(matcher.isConditionExpression("Hello World"));
    }

    @Test
    void detectsTerminationTrapsAcrossArchitectures() {
        // ARM Thumb bkpt and branch-to-self
        StackInstruction armBkpt = StackInstruction.arm(0x08001000L, "bkpt", "#0");
        assertTrue(matcher.isTerminationInstruction(armBkpt));

        StackInstruction armLoop = StackInstruction.arm(0x08001002L, "b", ".");
        assertTrue(matcher.isTerminationInstruction(armLoop));

        // RISC-V ebreak and unimp
        StackInstruction riscvEbreak = StackInstruction.riscv(0x1000L, "ebreak");
        assertTrue(matcher.isTerminationInstruction(riscvEbreak));

        StackInstruction riscvLoop = StackInstruction.riscv(0x1002L, "j", ".");
        assertTrue(matcher.isTerminationInstruction(riscvLoop));

        // Xtensa break.n
        StackInstruction xtensaBreak = StackInstruction.xtensa(0x40081000L, "break.n", "1");
        assertTrue(matcher.isTerminationInstruction(xtensaBreak));

        StackInstruction normal = StackInstruction.arm(0x08001004L, "nop");
        assertFalse(matcher.isTerminationInstruction(normal));
    }

    @Test
    void classifiesAssertWithFileAndLineAndTrap() {
        Map<String, String> args = Map.of(
                "file", "main.c",
                "line", "123",
                "expression", "val != NULL"
        );
        List<StackInstruction> following = List.of(
                StackInstruction.arm(0x08001020L, "bkpt", "#0")
        );

        DiagnosticLogLevel level = matcher.classifyAssertOrPanic("sub_08000500", args, following);
        assertEquals(DiagnosticLogLevel.ASSERT, level);
    }
}
