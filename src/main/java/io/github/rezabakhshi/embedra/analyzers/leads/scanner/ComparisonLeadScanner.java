package io.github.rezabakhshi.embedra.analyzers.leads.scanner;

import io.github.rezabakhshi.embedra.analyzers.leads.HeuristicFactor;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadCategory;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadConfidence;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans function disassembly for candidate password/token comparisons and authorization branches (AN-005).
 */
public final class ComparisonLeadScanner {

    private static final int DEFAULT_SCAN_WINDOW_DEPTH = 32;

    private static final Pattern RAW_HEX_PATTERN = Pattern.compile("0x([0-9a-fA-F]+)");

    private static final Pattern HEX_OR_DEC_PATTERN = Pattern.compile("#(?:0x([0-9a-fA-F]+)|(-?\\d+))");

    private static final Pattern STRING_LITERAL_PATTERN = Pattern.compile("\"([^\"]*)\"");

    private static final Set<String> KNOWN_STRING_COMPARE = Set.of(
            "strcmp", "strncmp", "strcasecmp", "strncasecmp", "wcscmp", "wcsncmp");

    private static final Set<String> KNOWN_MEM_COMPARE = Set.of(
            "memcmp", "bcmp");

    private static final Set<String> KNOWN_CRYPTO_COMPARE = Set.of(
            "crypto_memcmp", "timingsafe_bcmp", "timingsafe_memcmp", "mbedtls_ct_memcmp",
            "mbedtls_ssl_safer_memcmp", "constant_time_memcmp");

    private static final Set<String> SENSITIVE_KEYWORDS = Set.of(
            "password", "passwd", "pass", "pwd", "secret", "token", "pin", "auth",
            "key", "admin", "root", "flag", "credential", "login", "master", "super");

    private final int scanWindowDepth;

    public ComparisonLeadScanner() {
        this(DEFAULT_SCAN_WINDOW_DEPTH);
    }

    public ComparisonLeadScanner(int scanWindowDepth) {
        this.scanWindowDepth = Math.max(4, scanWindowDepth);
    }

    /**
     * Scans instructions in a function for candidate comparison and authorization leads.
     */
    public List<SecurityLead> scanFunction(
            long functionAddress,
            List<StackInstruction> instructions,
            Map<Long, String> stringTable,
            Map<Long, String> symbolMap,
            InstructionArch arch,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(instructions, "instructions must not be null");
        Objects.requireNonNull(stringTable, "stringTable must not be null");
        Objects.requireNonNull(symbolMap, "symbolMap must not be null");
        Objects.requireNonNull(arch, "arch must not be null");
        Objects.requireNonNull(limits, "limits must not be null");

        List<SecurityLead> leads = new ArrayList<>();
        int leadCounter = 1;

        for (int i = 0; i < instructions.size(); i++) {
            if (token != null && token.isCancellationRequested()) {
                token.throwIfCancellationRequested();
            }
            if (leads.size() >= limits.maxObjects()) {
                break;
            }

            StackInstruction instr = instructions.get(i);
            if (!isCallInstruction(instr)) {
                continue;
            }

            String targetSymbol = extractTargetSymbol(instr, symbolMap);
            long targetAddr = extractTargetAddress(instr);
            String lowerSymbol = targetSymbol.toLowerCase(Locale.ROOT);

            boolean isStringCmp = KNOWN_STRING_COMPARE.contains(lowerSymbol);
            boolean isMemCmp = KNOWN_MEM_COMPARE.contains(lowerSymbol);
            boolean isCryptoCmp = KNOWN_CRYPTO_COMPARE.contains(lowerSymbol);
            boolean isCustomAuth = isCustomAuthFunction(lowerSymbol);

            if (!isStringCmp && !isMemCmp && !isCryptoCmp && !isCustomAuth) {
                continue;
            }

            // Resolve operand registers
            Map<String, ResolvedOperand> operands = trackPrecedingRegisters(instructions, i, arch);

            // Determine if any operand is a constant or static string
            String staticOperandString = null;
            long staticOperandAddr = 0;
            boolean hasDynamicOperand = false;

            for (int argIdx = 0; argIdx < 2; argIdx++) {
                String regName = argumentRegisterName(argIdx, arch);
                ResolvedOperand op = operands.get(regName);
                if (op != null) {
                    if (op.hasLiteralString()) {
                        staticOperandString = op.literalString();
                    } else if (op.hasImmediate()) {
                        long imm = op.immediate();
                        if (stringTable.containsKey(imm)) {
                            staticOperandString = stringTable.get(imm);
                            staticOperandAddr = imm;
                        }
                    } else {
                        hasDynamicOperand = true;
                    }
                } else {
                    hasDynamicOperand = true;
                }
            }

            boolean sensitiveTarget = staticOperandString != null && containsSensitiveKeyword(staticOperandString);
            boolean sensitiveSymbol = containsSensitiveKeyword(lowerSymbol);

            // Check lookahead for conditional branch (authorization branch)
            BranchTarget authBranch = findImmediateConditionalBranch(instructions, i, arch);

            if (sensitiveTarget || sensitiveSymbol || isCryptoCmp || (isCustomAuth && staticOperandString != null)) {
                List<HeuristicFactor> factors = new ArrayList<>();
                double score = 0.0;

                if (isCryptoCmp) {
                    factors.add(HeuristicFactor.of("CONSTANT_TIME_COMPARE",
                            "Constant-time cryptographic memory comparison identified (" + targetSymbol + ")", 0.35));
                    score += 0.35;
                } else if (isStringCmp || isMemCmp) {
                    factors.add(HeuristicFactor.of("KNOWN_COMPARISON_FUNCTION",
                            "Standard comparison function identified (" + targetSymbol + ")", 0.25));
                    score += 0.25;
                } else {
                    factors.add(HeuristicFactor.of("CUSTOM_AUTH_FUNCTION",
                            "Custom verification function identified (" + targetSymbol + ")", 0.30));
                    score += 0.30;
                }

                if (sensitiveTarget) {
                    factors.add(HeuristicFactor.of("HARDCODED_SECRET_OPERAND",
                            "Comparison compares input against hardcoded string candidate: \""
                                    + sanitize(staticOperandString) + "\"", 0.40));
                    score += 0.40;
                }

                if (sensitiveSymbol) {
                    factors.add(HeuristicFactor.of("SENSITIVE_KEYWORD_MATCH",
                            "Symbol name contains sensitive authentication keyword (" + targetSymbol + ")", 0.20));
                    score += 0.20;
                }

                if (hasDynamicOperand && staticOperandString != null) {
                    factors.add(HeuristicFactor.of("ASYMMETRIC_COMPARISON",
                            "Asymmetric comparison between static constant and variable operand", 0.15));
                    score += 0.15;
                }

                if (authBranch != null) {
                    factors.add(HeuristicFactor.of("CONDITIONAL_BRANCH_EVALUATION",
                            "Immediate conditional branch evaluates comparison outcome at 0x"
                                    + Long.toHexString(authBranch.branchAddress), 0.20));
                    score += 0.20;
                }

                double normalizedScore = Math.min(1.0, score);
                LeadConfidence conf = LeadConfidence.fromScore(normalizedScore);
                LeadSeverity sev = (sensitiveTarget && (sensitiveSymbol || isCryptoCmp))
                        ? LeadSeverity.CRITICAL : LeadSeverity.HIGH;

                String leadId = String.format("LEAD-CMP-%04d", leadCounter++);
                String targetStr = staticOperandString != null ? staticOperandString : targetSymbol;
                String desc = String.format(
                        "Candidate password/token comparison at 0x%X calling %s against \"%s\"",
                        instr.address(), targetSymbol.isBlank() ? "0x" + Long.toHexString(targetAddr) : targetSymbol,
                        sanitize(targetStr));

                Map<String, String> attrs = new HashMap<>();
                attrs.put("comparator", targetSymbol);
                attrs.put("comparatorAddress", "0x" + Long.toHexString(targetAddr));
                if (staticOperandAddr > 0) {
                    attrs.put("staticOperandAddress", "0x" + Long.toHexString(staticOperandAddr));
                }
                if (authBranch != null) {
                    attrs.put("authBranchAddress", "0x" + Long.toHexString(authBranch.branchAddress));
                    attrs.put("branchMnemonic", authBranch.mnemonic);
                    attrs.put("targetTaken", "0x" + Long.toHexString(authBranch.targetTaken));
                    attrs.put("targetFallthrough", "0x" + Long.toHexString(authBranch.targetFallthrough));
                }

                leads.add(new SecurityLead(
                        leadId,
                        LeadCategory.PASSWORD_TOKEN_COMPARISON,
                        conf,
                        normalizedScore,
                        sev,
                        instr.address(),
                        targetSymbol,
                        targetStr,
                        desc,
                        factors,
                        attrs,
                        staticOperandString != null));

                // Add corresponding Authorization Branch lead if branch was discovered
                if (authBranch != null) {
                    List<HeuristicFactor> branchFactors = List.of(
                            HeuristicFactor.of("BRANCH_AFTER_CREDENTIAL_COMPARE",
                                    "Conditional branch directly gates execution based on comparison result", 0.50),
                            HeuristicFactor.of("GATE_DECISION_PATH",
                                    "Diverges to success path 0x" + Long.toHexString(authBranch.targetTaken)
                                            + " or rejection path 0x"
                                            + Long.toHexString(authBranch.targetFallthrough), 0.35));
                    double branchScore = Math.min(1.0, normalizedScore * 0.95);
                    String branchLeadId = String.format("LEAD-AUTH-%04d", leadCounter++);
                    String branchDesc = String.format(
                            "Candidate authorization branch at 0x%X testing %s comparison result (target: 0x%X)",
                            authBranch.branchAddress, authBranch.mnemonic, authBranch.targetTaken);

                    leads.add(new SecurityLead(
                            branchLeadId,
                            LeadCategory.AUTHORIZATION_BRANCH,
                            LeadConfidence.fromScore(branchScore),
                            branchScore,
                            LeadSeverity.HIGH,
                            authBranch.branchAddress,
                            targetSymbol,
                            authBranch.mnemonic,
                            branchDesc,
                            branchFactors,
                            attrs,
                            false));
                }
            }
        }

        return List.copyOf(leads);
    }

    private static boolean isCustomAuthFunction(String symbol) {
        return symbol.contains("check_pass")
                || symbol.contains("verify_pass")
                || symbol.contains("check_password")
                || symbol.contains("verify_pin")
                || symbol.contains("auth_check")
                || symbol.contains("validate_token")
                || symbol.contains("cmp_secret")
                || symbol.contains("login_verify");
    }

    private static boolean containsSensitiveKeyword(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        for (String kw : SENSITIVE_KEYWORDS) {
            if (lower.contains(kw)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCallInstruction(StackInstruction instr) {
        String m = instr.mnemonic().toLowerCase(Locale.ROOT);
        return switch (instr.architecture()) {
            case ARM_THUMB -> m.equals("bl") || m.equals("blx");
            case RISCV32 -> m.equals("call") || m.equals("jal") || m.equals("jalr");
            case XTENSA -> m.startsWith("call");
        };
    }

    private static String extractTargetSymbol(StackInstruction instr, Map<Long, String> symbolMap) {
        long targetAddr = extractTargetAddress(instr);
        if (targetAddr > 0 && symbolMap.containsKey(targetAddr)) {
            return symbolMap.get(targetAddr);
        }
        List<String> ops = instr.operands();
        if (ops.isEmpty()) {
            return "";
        }
        String op = ops.get(ops.size() - 1).trim();
        if (op.startsWith("0x") || op.matches("^\\d+$")) {
            return "";
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
                // fall through
            }
        }
        return 0L;
    }

    private static String argumentRegisterName(int index, InstructionArch arch) {
        return switch (arch) {
            case ARM_THUMB -> "r" + index;
            case RISCV32 -> "a" + index;
            case XTENSA -> "a" + (index + 2);
        };
    }

    private static String normalizeReg(String raw, InstructionArch arch) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim().toLowerCase(Locale.ROOT);
        if (s.endsWith(",")) {
            s = s.substring(0, s.length() - 1).trim();
        }
        if (arch == InstructionArch.ARM_THUMB && s.matches("^r[0-7]$")) {
            return s;
        }
        if (arch == InstructionArch.RISCV32 && s.matches("^a[0-7]$")) {
            return s;
        }
        if (arch == InstructionArch.XTENSA && s.matches("^a(?:[2-9]|1[0-5])$")) {
            return s;
        }
        return null;
    }

    private Map<String, ResolvedOperand> trackPrecedingRegisters(
            List<StackInstruction> instructions,
            int callIndex,
            InstructionArch arch) {
        Map<String, ResolvedOperand> map = new HashMap<>();
        int start = Math.max(0, callIndex - scanWindowDepth);

        for (int i = callIndex - 1; i >= start; i--) {
            StackInstruction instr = instructions.get(i);
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
                continue;
            }

            String strLiteral = extractStringLiteral(ops);
            if (strLiteral != null) {
                map.put(destReg, ResolvedOperand.ofLiteral(strLiteral));
                continue;
            }

            if (arch == InstructionArch.ARM_THUMB) {
                if (mnemonic.startsWith("movs") || mnemonic.equals("mov")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, ResolvedOperand.ofImmediate(imm));
                    }
                } else if (mnemonic.startsWith("ldr") || mnemonic.startsWith("adr")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, ResolvedOperand.ofImmediate(imm));
                    }
                }
            } else if (arch == InstructionArch.RISCV32) {
                if (mnemonic.equals("li") || mnemonic.equals("la") || mnemonic.equals("lla")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, ResolvedOperand.ofImmediate(imm));
                    }
                }
            } else if (arch == InstructionArch.XTENSA) {
                if (mnemonic.startsWith("movi") || mnemonic.startsWith("l32r")) {
                    Long imm = parseImmediate(ops.get(1));
                    if (imm != null) {
                        map.put(destReg, ResolvedOperand.ofImmediate(imm));
                    }
                }
            }
        }

        return map;
    }

    private static BranchTarget findImmediateConditionalBranch(
            List<StackInstruction> instructions,
            int callIndex,
            InstructionArch arch) {
        int end = Math.min(instructions.size(), callIndex + 6);
        for (int i = callIndex + 1; i < end; i++) {
            StackInstruction instr = instructions.get(i);
            String m = instr.mnemonic().toLowerCase(Locale.ROOT);
            boolean isBranch = switch (arch) {
                case ARM_THUMB -> m.startsWith("cbz") || m.startsWith("cbnz")
                        || m.equals("beq") || m.equals("bne") || m.equals("b.eq") || m.equals("b.ne");
                case RISCV32 -> m.equals("beqz") || m.equals("bnez") || m.equals("beq") || m.equals("bne");
                case XTENSA -> m.startsWith("beqz") || m.startsWith("bnez")
                        || m.startsWith("beqi") || m.startsWith("bnei");
            };

            if (isBranch) {
                long target = extractTargetAddress(instr);
                long fallthrough = i + 1 < instructions.size()
                        ? instructions.get(i + 1).address() : instr.address() + 2;
                return new BranchTarget(instr.address(), m, target, fallthrough);
            }
            if (isCallInstruction(instr)) {
                break;
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

    private static Long parseImmediate(String op) {
        if (op == null) {
            return null;
        }
        Matcher hexOrDec = HEX_OR_DEC_PATTERN.matcher(op.trim());
        if (hexOrDec.find()) {
            if (hexOrDec.group(1) != null) {
                try {
                    return Long.parseUnsignedLong(hexOrDec.group(1), 16);
                } catch (NumberFormatException ignored) {
                    // fall through
                }
            } else if (hexOrDec.group(2) != null) {
                try {
                    return Long.parseLong(hexOrDec.group(2));
                } catch (NumberFormatException ignored) {
                    // fall through
                }
            }
        }
        Matcher rawHex = RAW_HEX_PATTERN.matcher(op.trim());
        if (rawHex.find()) {
            try {
                return Long.parseUnsignedLong(rawHex.group(1), 16);
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        return null;
    }

    private static String sanitize(String s) {
        return s.replace("\n", "\\n").replace("\r", "\\r");
    }

    private record BranchTarget(long branchAddress, String mnemonic, long targetTaken, long targetFallthrough) {
    }

    private static final class ResolvedOperand {

        private final Long immediate;

        private final String literalString;

        private ResolvedOperand(Long immediate, String literalString) {
            this.immediate = immediate;
            this.literalString = literalString;
        }

        static ResolvedOperand ofImmediate(long imm) {
            return new ResolvedOperand(imm, null);
        }

        static ResolvedOperand ofLiteral(String lit) {
            return new ResolvedOperand(null, lit);
        }

        boolean hasImmediate() {
            return immediate != null;
        }

        long immediate() {
            return immediate;
        }

        boolean hasLiteralString() {
            return literalString != null;
        }

        String literalString() {
            return literalString;
        }
    }
}
