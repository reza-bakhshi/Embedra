package io.github.rezabakhshi.embedra.analyzers.logging.linkage;

import io.github.rezabakhshi.embedra.analyzers.logging.DiagnosticLogLevel;
import io.github.rezabakhshi.embedra.analyzers.logging.FormatStringDescriptor;
import io.github.rezabakhshi.embedra.analyzers.logging.LoggingCallSite;
import io.github.rezabakhshi.embedra.analyzers.logging.scanner.AssertPanicPatternMatcher;
import io.github.rezabakhshi.embedra.analyzers.logging.scanner.FormatStringParser;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves calling conventions, arguments, format strings, and assert idioms across architectures (AN-004).
 */
public final class CallSiteArgumentResolver {

    private static final int DEFAULT_SCAN_WINDOW_DEPTH = 32;

    private static final Pattern HEX_OR_DEC_PATTERN = Pattern.compile(
            "#(?:0x([0-9a-fA-F]+)|(-?\\d+))");

    private static final Pattern RAW_HEX_PATTERN = Pattern.compile(
            "0x([0-9a-fA-F]+)");

    private static final Pattern STRING_LITERAL_PATTERN = Pattern.compile(
            "\"([^\"]*)\"");

    private final FormatStringParser formatParser;

    private final AssertPanicPatternMatcher assertMatcher;

    private final int scanWindowDepth;

    public CallSiteArgumentResolver() {
        this(DEFAULT_SCAN_WINDOW_DEPTH);
    }

    public CallSiteArgumentResolver(int scanWindowDepth) {
        this.scanWindowDepth = Math.max(4, scanWindowDepth);
        this.formatParser = new FormatStringParser();
        this.assertMatcher = new AssertPanicPatternMatcher();
    }

    /**
     * Analyzes a list of instructions in a function to discover and link logging and assert call sites.
     *
     * @param functionAddress entry address of the function
     * @param instructions instruction sequence
     * @param stringTable table mapping memory addresses to string contents
     * @param limits parser limits
     * @param token cancellation token
     * @return list of recovered logging call sites
     */
    public List<LoggingCallSite> resolveCallSites(
            long functionAddress,
            List<StackInstruction> instructions,
            Map<Long, String> stringTable,
            ParserLimits limits,
            CancellationToken token) throws io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException {
        Objects.requireNonNull(instructions, "instructions must not be null");
        stringTable = stringTable == null ? Map.of() : stringTable;
        limits = limits == null ? ParserLimits.defaults() : limits;
        token = token == null ? CancellationToken.none() : token;

        List<LoggingCallSite> results = new ArrayList<>();
        int count = instructions.size();

        for (int i = 0; i < count; i++) {
            token.throwIfCancellationRequested();
            if (results.size() >= limits.maxObjects()) {
                break;
            }

            StackInstruction instr = instructions.get(i);
            if (!isCallInstruction(instr)) {
                continue;
            }

            String targetSymbol = extractTargetSymbol(instr);
            long targetAddr = extractTargetAddress(instr);

            // Backward register analysis
            Map<String, ResolvedArg> regValues = trackPrecedingRegisters(instructions, i, instr.architecture());

            // Map registers to argument indices
            List<ResolvedArg> orderedArgs = mapRegistersToArgs(regValues, instr);

            // Map resolved values to strings/numbers
            Map<String, String> resolvedArgMap = new HashMap<>();
            String formatCandidate = null;
            int formatArgIndex = -1;

            for (int argIdx = 0; argIdx < orderedArgs.size(); argIdx++) {
                ResolvedArg r = orderedArgs.get(argIdx);
                if (r == null) {
                    continue;
                }

                String strVal = r.stringContent();
                if (strVal == null && r.hasAddress() && stringTable.containsKey(r.address())) {
                    strVal = stringTable.get(r.address());
                }

                if (strVal != null) {
                    if (assertMatcher.isSourceFileName(strVal) && !resolvedArgMap.containsKey("file")) {
                        resolvedArgMap.put("file", strVal);
                    } else if (assertMatcher.isConditionExpression(strVal)
                            && !resolvedArgMap.containsKey("expression")) {
                        resolvedArgMap.put("expression", strVal);
                    } else if (formatCandidate == null && containsFormatSpecifier(strVal)) {
                        formatCandidate = strVal;
                        formatArgIndex = argIdx;
                    } else if (argIdx == 0 && (targetSymbol.toLowerCase(Locale.ROOT).contains("esp_log")
                            || targetSymbol.toLowerCase(Locale.ROOT).contains("tag"))) {
                        resolvedArgMap.put("tag", strVal);
                    } else if (!resolvedArgMap.containsKey("message")) {
                        resolvedArgMap.put("message", strVal);
                    }
                }

                if (r.hasImmediate() && assertMatcher.isLineNumber(r.immediate())
                        && !resolvedArgMap.containsKey("line")) {
                    resolvedArgMap.put("line", String.valueOf(r.immediate()));
                }
            }

            // Lookahead for termination traps (e.g. bkpt, ebreak, branch to self)
            List<StackInstruction> following = getFollowingInstructions(instructions, i, 3);

            // Check 1: Assert or Panic
            DiagnosticLogLevel assertLevel = assertMatcher.classifyAssertOrPanic(
                    targetSymbol, resolvedArgMap, following);

            if (assertLevel != null) {
                String conf = assertMatcher.isAssertFunction(targetSymbol)
                        || assertMatcher.isPanicFunction(targetSymbol)
                        ? "CONFIRMED" : "LIKELY";
                String expl = String.format("%s idiom detected at call 0x%X",
                        assertLevel.name(), instr.address());

                FormatStringDescriptor fmtDesc = formatCandidate != null
                        ? formatParser.parse(formatCandidate, limits)
                        : FormatStringDescriptor.empty();

                results.add(new LoggingCallSite(
                        instr.address(),
                        targetAddr,
                        targetSymbol,
                        assertLevel,
                        fmtDesc,
                        resolvedArgMap,
                        conf,
                        expl));
                continue;
            }

            // Check 2: Logging / Printf call
            boolean isLogFunc = isLoggingFunction(targetSymbol);
            if (isLogFunc || formatCandidate != null) {
                DiagnosticLogLevel logLevel = classifyLogLevel(targetSymbol, formatCandidate);
                String conf;
                if (isLogFunc && formatCandidate != null) {
                    conf = "CONFIRMED";
                } else if (formatCandidate != null) {
                    conf = "LIKELY";
                } else {
                    conf = "PLAUSIBLE";
                }

                FormatStringDescriptor fmtDesc = formatCandidate != null
                        ? formatParser.parse(formatCandidate, limits)
                        : (resolvedArgMap.containsKey("message")
                        ? FormatStringDescriptor.plain(resolvedArgMap.get("message"))
                        : FormatStringDescriptor.empty());

                String expl = String.format("Logging call (%s) at 0x%X to %s",
                        logLevel.name(), instr.address(),
                        targetSymbol.isBlank() ? String.format("0x%X", targetAddr) : targetSymbol);

                results.add(new LoggingCallSite(
                        instr.address(),
                        targetAddr,
                        targetSymbol,
                        logLevel,
                        fmtDesc,
                        resolvedArgMap,
                        conf,
                        expl));
            }
        }

        return List.copyOf(results);
    }

    private static boolean isCallInstruction(StackInstruction instr) {
        String m = instr.mnemonic().toLowerCase(Locale.ROOT);
        return switch (instr.architecture()) {
            case ARM_THUMB -> m.equals("bl") || m.equals("blx");
            case RISCV32 -> m.equals("call") || m.equals("jal") || m.equals("jalr");
            case XTENSA -> m.startsWith("call");
        };
    }

    private static String extractTargetSymbol(StackInstruction instr) {
        List<String> ops = instr.operands();
        if (ops.isEmpty()) {
            return "";
        }
        String op = ops.get(ops.size() - 1).trim();
        // If operand is purely numeric or hex address, it's not a symbol
        if (op.startsWith("0x") || op.matches("^\\d+$")) {
            return "";
        }
        // Ghidra symbol reference formatting
        if (op.startsWith("sub_") || op.startsWith("FUN_")) {
            return op;
        }
        return op;
    }

    private static long extractTargetAddress(StackInstruction instr) {
        List<String> ops = instr.operands();
        if (ops.isEmpty()) {
            return 0L;
        }
        String op = ops.get(ops.size() - 1).trim();
        Matcher m = RAW_HEX_PATTERN.matcher(op);
        if (m.find()) {
            try {
                return Long.parseUnsignedLong(m.group(1), 16);
            } catch (NumberFormatException ignored) {
                // Return 0
            }
        }
        return 0L;
    }

    private Map<String, ResolvedArg> trackPrecedingRegisters(
            List<StackInstruction> instructions,
            int callIndex,
            InstructionArch arch) {
        Map<String, ResolvedArg> map = new HashMap<>();
        int start = Math.max(0, callIndex - scanWindowDepth);

        for (int i = callIndex - 1; i >= start; i--) {
            StackInstruction instr = instructions.get(i);
            // Stop at another call instruction
            if (isCallInstruction(instr)) {
                break;
            }

            String mnemonic = instr.mnemonic().toLowerCase(Locale.ROOT);
            List<String> ops = instr.operands();
            if (ops.size() < 2) {
                continue;
            }

            String destReg = normalizeReg(ops.get(0), arch);
            if (destReg == null || map.containsKey(destReg)) {
                // If destination register is already resolved from a closer instruction, do not overwrite
                continue;
            }

            // Check if string literal appears directly in operands
            String strLiteral = extractStringLiteral(ops);

            // ARM instructions
            if (arch == InstructionArch.ARM_THUMB) {
                if (mnemonic.startsWith("movs") || mnemonic.equals("mov")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, new ResolvedArg(null, imm, strLiteral));
                    }
                } else if (mnemonic.equals("movw")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, new ResolvedArg(imm, imm, strLiteral));
                    }
                } else if (mnemonic.equals("movt")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        // Check if movw already resolved lower bits
                        ResolvedArg existing = map.get(destReg);
                        long val = (imm << 16);
                        if (existing != null && existing.hasImmediate()) {
                            val |= (existing.immediate() & 0xFFFFL);
                        }
                        map.put(destReg, new ResolvedArg(val, val, strLiteral));
                    }
                } else if (mnemonic.startsWith("ldr") || mnemonic.startsWith("adr")) {
                    Long addr = parseAddressOrLiteral(ops.get(1));
                    if (addr != null) {
                        map.put(destReg, new ResolvedArg(addr, null, strLiteral));
                    } else if (strLiteral != null) {
                        map.put(destReg, new ResolvedArg(null, null, strLiteral));
                    }
                }
            } else if (arch == InstructionArch.RISCV32) {
                if (mnemonic.equals("li")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, new ResolvedArg(imm, imm, strLiteral));
                    }
                } else if (mnemonic.equals("lui")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, new ResolvedArg(imm << 12, null, strLiteral));
                    }
                } else if (mnemonic.equals("addi") && ops.size() >= 3) {
                    Long imm = parseImmediate(ops.get(2));
                    String srcReg = normalizeReg(ops.get(1), arch);
                    ResolvedArg src = map.get(srcReg);
                    if (src != null && src.hasAddress() && imm != null) {
                        long total = src.address() + imm;
                        map.put(destReg, new ResolvedArg(total, total, strLiteral));
                    } else if (imm != null) {
                        map.put(destReg, new ResolvedArg(null, imm, strLiteral));
                    }
                } else if (mnemonic.equals("la") || mnemonic.equals("lla")) {
                    Long addr = parseAddressOrLiteral(ops.get(1));
                    map.put(destReg, new ResolvedArg(addr, null, strLiteral));
                }
            } else if (arch == InstructionArch.XTENSA) {
                if (mnemonic.startsWith("movi")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, new ResolvedArg(imm, imm, strLiteral));
                    }
                } else if (mnemonic.startsWith("l32r")) {
                    Long addr = parseAddressOrLiteral(ops.get(1));
                    map.put(destReg, new ResolvedArg(addr, null, strLiteral));
                }
            }
        }
        return map;
    }

    private static List<ResolvedArg> mapRegistersToArgs(
            Map<String, ResolvedArg> regMap,
            StackInstruction callInstr) {
        List<ResolvedArg> list = new ArrayList<>();
        InstructionArch arch = callInstr.architecture();

        switch (arch) {
            case ARM_THUMB -> {
                list.add(regMap.get("r0"));
                list.add(regMap.get("r1"));
                list.add(regMap.get("r2"));
                list.add(regMap.get("r3"));
            }
            case RISCV32 -> {
                list.add(regMap.get("a0"));
                list.add(regMap.get("a1"));
                list.add(regMap.get("a2"));
                list.add(regMap.get("a3"));
                list.add(regMap.get("a4"));
                list.add(regMap.get("a5"));
                list.add(regMap.get("a6"));
                list.add(regMap.get("a7"));
            }
            case XTENSA -> {
                String m = callInstr.mnemonic().toLowerCase(Locale.ROOT);
                if (m.equals("call4")) {
                    list.add(regMap.get("a6"));
                    list.add(regMap.get("a7"));
                    list.add(regMap.get("a8"));
                    list.add(regMap.get("a9"));
                } else if (m.equals("call8")) {
                    list.add(regMap.get("a10"));
                    list.add(regMap.get("a11"));
                    list.add(regMap.get("a12"));
                    list.add(regMap.get("a13"));
                } else {
                    list.add(regMap.get("a2"));
                    list.add(regMap.get("a3"));
                    list.add(regMap.get("a4"));
                    list.add(regMap.get("a5"));
                    list.add(regMap.get("a6"));
                    list.add(regMap.get("a7"));
                }
            }
        }
        return list;
    }

    private static String normalizeReg(String reg, InstructionArch arch) {
        if (reg == null) {
            return null;
        }
        String clean = reg.trim().toLowerCase(Locale.ROOT).replace(",", "");
        if (arch == InstructionArch.ARM_THUMB) {
            if (clean.matches("r[0-3]")) {
                return clean;
            }
        } else if (arch == InstructionArch.RISCV32) {
            if (clean.matches("a[0-7]")) {
                return clean;
            }
        } else if (arch == InstructionArch.XTENSA) {
            if (clean.matches("a(?:[0-9]|1[0-5])")) {
                return clean;
            }
        }
        return null;
    }

    private static Long parseImmediate(String op) {
        if (op == null) {
            return null;
        }
        String clean = op.trim();
        Matcher m = HEX_OR_DEC_PATTERN.matcher(clean);
        if (m.matches()) {
            if (m.group(1) != null) {
                return Long.parseUnsignedLong(m.group(1), 16);
            } else if (m.group(2) != null) {
                return Long.parseLong(m.group(2));
            }
        }
        Matcher rawHex = RAW_HEX_PATTERN.matcher(clean);
        if (rawHex.find()) {
            try {
                return Long.parseUnsignedLong(rawHex.group(1), 16);
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        try {
            return Long.parseLong(clean.replace("#", ""));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static Long parseAddressOrLiteral(String op) {
        if (op == null) {
            return null;
        }
        Matcher rawHex = RAW_HEX_PATTERN.matcher(op);
        if (rawHex.find()) {
            try {
                return Long.parseUnsignedLong(rawHex.group(1), 16);
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        return null;
    }

    private static String extractStringLiteral(List<String> ops) {
        for (String op : ops) {
            Matcher m = STRING_LITERAL_PATTERN.matcher(op);
            if (m.find()) {
                return m.group(1);
            }
        }
        return null;
    }

    private static boolean containsFormatSpecifier(String str) {
        if (str == null || str.length() < 2) {
            return false;
        }
        return str.contains("%s") || str.contains("%d") || str.contains("%u")
                || str.contains("%x") || str.contains("%X") || str.contains("%p")
                || str.contains("%i") || str.contains("%f") || str.contains("%02");
    }

    private static boolean isLoggingFunction(String symbol) {
        if (symbol == null || symbol.isBlank()) {
            return false;
        }
        String s = symbol.toLowerCase(Locale.ROOT);
        return s.contains("printf") || s.contains("printk") || s.contains("log")
                || s.contains("puts") || s.contains("trace") || s.contains("debug");
    }

    private static DiagnosticLogLevel classifyLogLevel(String symbol, String format) {
        String sym = symbol == null ? "" : symbol.toLowerCase(Locale.ROOT);
        String fmt = format == null ? "" : format.trim();

        if (sym.contains("loge") || sym.contains("err") || sym.contains("fatal")
                || fmt.startsWith("[E]") || fmt.startsWith("ERROR:") || fmt.startsWith("E:")) {
            return DiagnosticLogLevel.ERROR;
        }
        if (sym.contains("logw") || sym.contains("warn")
                || fmt.startsWith("[W]") || fmt.startsWith("WARN:") || fmt.startsWith("W:")) {
            return DiagnosticLogLevel.WARNING;
        }
        if (sym.contains("logi") || sym.contains("info")
                || fmt.startsWith("[I]") || fmt.startsWith("INFO:") || fmt.startsWith("I:")) {
            return DiagnosticLogLevel.INFO;
        }
        if (sym.contains("logd") || sym.contains("dbg") || sym.contains("debug") || sym.contains("trace")
                || sym.contains("logv") || fmt.startsWith("[D]") || fmt.startsWith("DEBUG:") || fmt.startsWith("D:")) {
            return DiagnosticLogLevel.DEBUG;
        }
        return DiagnosticLogLevel.INFO;
    }

    private static List<StackInstruction> getFollowingInstructions(
            List<StackInstruction> instructions, int currentIndex, int maxLookahead) {
        List<StackInstruction> list = new ArrayList<>();
        int end = Math.min(instructions.size(), currentIndex + 1 + maxLookahead);
        for (int i = currentIndex + 1; i < end; i++) {
            list.add(instructions.get(i));
        }
        return list;
    }

    private record ResolvedArg(Long address, Long immediate, String stringContent) {
        boolean hasAddress() {
            return address != null;
        }

        boolean hasImmediate() {
            return immediate != null;
        }
    }
}
