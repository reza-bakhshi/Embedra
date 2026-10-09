package io.github.rezabakhshi.embedra.analyzers.logging.scanner;

import io.github.rezabakhshi.embedra.analyzers.logging.DiagnosticLogLevel;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Identifies assert and panic call idioms, signature functions, and trailing termination traps (AN-004).
 */
public final class AssertPanicPatternMatcher {

    private static final Set<String> PANIC_SYMBOLS = Set.of(
            "panic", "hard_assert", "panic_at", "k_panic",
            "abort", "esp_system_abort", "abort_report",
            "halt", "die", "fatal_error", "vApplicationStackOverflowHook");

    private static final Set<String> ASSERT_SYMBOLS = Set.of(
            "assert", "__assert", "__assert_func", "__assert_fail",
            "__aeabi_assert", "configassert", "assert_param",
            "__assert_param", "z_assert_fail", "check_failed");

    private static final Pattern SOURCE_FILE_PATTERN = Pattern.compile(
            ".*\\.(c|cpp|cc|cxx|h|hpp)(\0|$)");

    private static final Pattern EXPRESSION_PATTERN = Pattern.compile(
            ".*(==|!=|<=|>=|<|>|!|&&|\\|\\||NULL|nullptr|\\b0\\b).*");

    public AssertPanicPatternMatcher() {
    }

    /**
     * Determines whether the given function symbol represents a panic or fatal abort function.
     */
    public boolean isPanicFunction(String symbol) {
        if (symbol == null || symbol.isBlank()) {
            return false;
        }
        String clean = cleanSymbol(symbol);
        if (PANIC_SYMBOLS.contains(clean)) {
            return true;
        }
        return clean.contains("panic") || clean.contains("abort") || clean.contains("fatal");
    }

    /**
     * Determines whether the given function symbol represents an assert function.
     */
    public boolean isAssertFunction(String symbol) {
        if (symbol == null || symbol.isBlank()) {
            return false;
        }
        String clean = cleanSymbol(symbol);
        if (ASSERT_SYMBOLS.contains(clean)) {
            return true;
        }
        return clean.contains("assert");
    }

    /**
     * Determines whether a string candidate is likely a source code filename.
     */
    public boolean isSourceFileName(String str) {
        if (str == null || str.isBlank() || str.length() > 256) {
            return false;
        }
        String lower = str.toLowerCase(Locale.ROOT).trim();
        return SOURCE_FILE_PATTERN.matcher(lower).matches()
                || ((lower.contains("/") || lower.contains("\\"))
                && (lower.endsWith(".c") || lower.endsWith(".h") || lower.endsWith(".cpp")));
    }

    /**
     * Determines whether an immediate value is likely a valid source code line number.
     */
    public boolean isLineNumber(long val) {
        return val >= 1 && val <= 500_000;
    }

    /**
     * Determines whether a string candidate is likely a failed assert condition expression.
     */
    public boolean isConditionExpression(String str) {
        if (str == null || str.isBlank() || str.length() > 200) {
            return false;
        }
        return EXPRESSION_PATTERN.matcher(str).matches();
    }

    /**
     * Identifies whether the instruction following a call is a termination instruction (trap/breakpoint/infinite loop).
     */
    public boolean isTerminationInstruction(StackInstruction instruction) {
        if (instruction == null) {
            return false;
        }
        String mnemonic = instruction.mnemonic().toLowerCase(Locale.ROOT);
        InstructionArch arch = instruction.architecture();

        switch (arch) {
            case ARM_THUMB -> {
                if (mnemonic.startsWith("bkpt") || mnemonic.startsWith("udf")) {
                    return true;
                }
                if (mnemonic.equals("b") || mnemonic.equals("b.w") || mnemonic.equals("b.n")) {
                    List<String> ops = instruction.operands();
                    if (!ops.isEmpty()) {
                        String target = ops.get(0).trim();
                        // Branch to self / infinite loop
                        if (".".equals(target) || "#0".equals(target) || "#-2".equals(target)
                                || target.equalsIgnoreCase(String.format("0x%x", instruction.address()))
                                || target.equalsIgnoreCase(String.format("0x%08x", instruction.address()))) {
                            return true;
                        }
                    }
                }
            }
            case RISCV32 -> {
                if (mnemonic.equals("ebreak") || mnemonic.equals("unimp")) {
                    return true;
                }
                if (mnemonic.equals("j") || mnemonic.equals("jal")) {
                    List<String> ops = instruction.operands();
                    if (!ops.isEmpty()) {
                        String target = ops.get(ops.size() - 1).trim();
                        if (".".equals(target) || "0".equals(target)
                                || target.equalsIgnoreCase(String.format("0x%x", instruction.address()))
                                || target.equalsIgnoreCase(String.format("0x%08x", instruction.address()))) {
                            return true;
                        }
                    }
                }
            }
            case XTENSA -> {
                if (mnemonic.startsWith("break") || mnemonic.equals("ill")) {
                    return true;
                }
                if (mnemonic.equals("j") || mnemonic.equals("loop")) {
                    List<String> ops = instruction.operands();
                    if (!ops.isEmpty()) {
                        String target = ops.get(ops.size() - 1).trim();
                        if (".".equals(target)
                                || target.equalsIgnoreCase(String.format("0x%x", instruction.address()))
                                || target.equalsIgnoreCase(String.format("0x%08x", instruction.address()))) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * Determines whether the combination of symbol, arguments, and following instructions is an assert or panic.
     */
    public DiagnosticLogLevel classifyAssertOrPanic(
            String targetSymbol,
            Map<String, String> resolvedArgs,
            List<StackInstruction> followingInstructions) {
        if (isPanicFunction(targetSymbol)) {
            return DiagnosticLogLevel.PANIC;
        }
        if (isAssertFunction(targetSymbol)) {
            return DiagnosticLogLevel.ASSERT;
        }

        boolean hasTermination = false;
        if (followingInstructions != null) {
            for (StackInstruction instr : followingInstructions) {
                if (isTerminationInstruction(instr)) {
                    hasTermination = true;
                    break;
                }
            }
        }

        boolean hasFileLine = resolvedArgs.containsKey("file") && resolvedArgs.containsKey("line");
        if (hasFileLine && hasTermination) {
            return DiagnosticLogLevel.ASSERT;
        }

        if (hasTermination && resolvedArgs.containsKey("message")) {
            return DiagnosticLogLevel.PANIC;
        }

        return null;
    }

    private static String cleanSymbol(String symbol) {
        String s = symbol.toLowerCase(Locale.ROOT).trim();
        if (s.startsWith("_")) {
            s = s.replaceAll("^_+", "");
        }
        return s;
    }
}
