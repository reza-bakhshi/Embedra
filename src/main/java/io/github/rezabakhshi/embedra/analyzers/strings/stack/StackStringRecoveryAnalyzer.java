package io.github.rezabakhshi.embedra.analyzers.strings.stack;

import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.Set;
import java.util.TreeMap;

/**
 * Pure analyzer for recovering stack-constructed strings across ARM Thumb, RISC-V, and Xtensa.
 *
 * <p>Emulates immediate stores into the function stack frame, reconstructs contiguous memory
 * buffers, decodes string contents, and attributes instruction spans under strict resource bounds.</p>
 */
public final class StackStringRecoveryAnalyzer {

    private record StackByteRecord(byte value, long instructionAddress, int instructionIndex) { }

    public StackStringRecoveryAnalyzer() {
    }

    /**
     * Recovers stack strings across multiple functions.
     */
    public List<RecoveredStackString> analyzeFunctions(
            Map<Long, List<StackInstruction>> functions,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(functions, "functions must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        Instant startTime = Instant.now();
        List<RecoveredStackString> allRecovered = new ArrayList<>();

        for (Map.Entry<Long, List<StackInstruction>> entry : functions.entrySet()) {
            token.throwIfCancellationRequested();
            if (Duration.between(startTime, Instant.now()).compareTo(limits.maxWallTime()) > 0
                    || allRecovered.size() >= limits.maxObjects()) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.LIMIT_EXCEEDED,
                        "Stack string recovery exceeded configured resource limits", null));
            }

            List<RecoveredStackString> recovered = analyzeFunction(
                    entry.getKey(), entry.getValue(), limits, token, startTime);
            allRecovered.addAll(recovered);
        }

        allRecovered.sort(Comparator.comparingLong(RecoveredStackString::functionAddress)
                .thenComparingLong(RecoveredStackString::stackOffset));
        return List.copyOf(allRecovered);
    }

    /**
     * Recovers stack strings from a single function disassembly stream.
     */
    public List<RecoveredStackString> analyzeFunction(
            long functionAddress,
            List<StackInstruction> instructions,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        return analyzeFunction(functionAddress, instructions, limits, token, Instant.now());
    }

    private List<RecoveredStackString> analyzeFunction(
            long functionAddress,
            List<StackInstruction> instructions,
            ParserLimits limits,
            CancellationToken token,
            Instant startTime) throws DiagnosticException {
        Objects.requireNonNull(instructions, "instructions must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        if (functionAddress < 0) {
            throw new IllegalArgumentException("Function address must not be negative");
        }

        int maxInstructions = Math.min((int) limits.maxObjects(), 10_000);
        int instructionCount = Math.min(instructions.size(), maxInstructions);

        Map<String, Long> registers = new HashMap<>();
        Map<String, Long> stackPointers = new HashMap<>();
        Map<Long, StackByteRecord> stackMemory = new TreeMap<>();

        // Initialize stack pointer bases
        stackPointers.put("sp", 0L);
        stackPointers.put("r13", 0L);
        stackPointers.put("x2", 0L);
        stackPointers.put("a1", 0L);

        for (int i = 0; i < instructionCount; i++) {
            if ((i & 0x7F) == 0) {
                token.throwIfCancellationRequested();
                if (Duration.between(startTime, Instant.now()).compareTo(limits.maxWallTime()) > 0) {
                    throw new DiagnosticException(Diagnostic.error(
                            DiagnosticCode.LIMIT_EXCEEDED,
                            "Stack string recovery exceeded wall time limit", null));
                }
            }

            StackInstruction instr = instructions.get(i);
            processInstruction(instr, i, registers, stackPointers, stackMemory);
        }

        return reconstructStrings(functionAddress, stackMemory);
    }

    private void processInstruction(
            StackInstruction instr,
            int instructionIndex,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        String mnem = instr.mnemonic();
        List<String> ops = instr.operands();
        InstructionArch arch = instr.architecture();

        switch (arch) {
            case ARM_THUMB -> processArmInstruction(instr, instructionIndex, mnem, ops,
                    registers, stackPointers, stackMemory);
            case RISCV32 -> processRiscvInstruction(instr, instructionIndex, mnem, ops,
                    registers, stackPointers, stackMemory);
            case XTENSA -> processXtensaInstruction(instr, instructionIndex, mnem, ops,
                    registers, stackPointers, stackMemory);
            case STM8 -> processStm8Instruction(instr, instructionIndex, mnem, ops,
                    registers, stackPointers, stackMemory);
            case AVR8 -> processAvrInstruction(instr, instructionIndex, mnem, ops,
                    registers, stackPointers, stackMemory);
        }
    }

    private void processArmInstruction(
            StackInstruction instr,
            int idx,
            String mnem,
            List<String> ops,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        String baseMnem = stripCondition(mnem);

        // Immediate / Register Loads
        if (baseMnem.equals("mov") || baseMnem.equals("movs")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                String src = ops.get(1);
                OptionalLong imm = parseImmediate(src);
                if (imm.isPresent()) {
                    registers.put(dest, imm.getAsLong() & 0xFFFFFFFFL);
                } else {
                    String srcReg = normalizeReg(src);
                    if (stackPointers.containsKey(srcReg)) {
                        stackPointers.put(dest, stackPointers.get(srcReg));
                    } else if (registers.containsKey(srcReg)) {
                        registers.put(dest, registers.get(srcReg));
                    } else {
                        registers.remove(dest);
                    }
                }
            }
            return;
        }

        if (baseMnem.equals("movw")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                parseImmediate(ops.get(1)).ifPresent(val -> registers.put(dest, val & 0xFFFFL));
            }
            return;
        }

        if (baseMnem.equals("movt")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                parseImmediate(ops.get(1)).ifPresent(val -> {
                    long cur = registers.getOrDefault(dest, 0L);
                    registers.put(dest, ((val & 0xFFFFL) << 16) | (cur & 0xFFFFL));
                });
            }
            return;
        }

        if (baseMnem.equals("mvn") || baseMnem.equals("mvns")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                parseImmediate(ops.get(1)).ifPresent(val -> registers.put(dest, (~val) & 0xFFFFFFFFL));
            }
            return;
        }

        if (baseMnem.equals("ldr")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                String src = ops.get(1);
                OptionalLong imm = parseImmediate(src);
                if (imm.isPresent()) {
                    registers.put(dest, imm.getAsLong() & 0xFFFFFFFFL);
                } else {
                    registers.remove(dest);
                }
            }
            return;
        }

        if (baseMnem.equals("add") || baseMnem.equals("adds")) {
            handleArmAdd(ops, registers, stackPointers);
            return;
        }

        if (baseMnem.equals("sub") || baseMnem.equals("subs")) {
            handleArmSub(ops, registers, stackPointers);
            return;
        }

        // Stores
        if (baseMnem.equals("strb")) {
            handleArmStore(instr.address(), idx, ops, 1, registers, stackPointers, stackMemory);
        } else if (baseMnem.equals("strh")) {
            handleArmStore(instr.address(), idx, ops, 2, registers, stackPointers, stackMemory);
        } else if (baseMnem.equals("str")) {
            handleArmStore(instr.address(), idx, ops, 4, registers, stackPointers, stackMemory);
        }
    }

    private void handleArmAdd(List<String> ops, Map<String, Long> registers, Map<String, Long> stackPointers) {
        if (ops.size() == 2) {
            String dest = normalizeReg(ops.get(0));
            OptionalLong imm = parseImmediate(ops.get(1));
            if (imm.isPresent()) {
                if (stackPointers.containsKey(dest)) {
                    stackPointers.put(dest, stackPointers.get(dest) + imm.getAsLong());
                } else if (registers.containsKey(dest)) {
                    registers.put(dest, (registers.get(dest) + imm.getAsLong()) & 0xFFFFFFFFL);
                }
            }
        } else if (ops.size() >= 3) {
            String dest = normalizeReg(ops.get(0));
            String src = normalizeReg(ops.get(1));
            OptionalLong imm = parseImmediate(ops.get(2));
            if (imm.isPresent()) {
                if (stackPointers.containsKey(src)) {
                    stackPointers.put(dest, stackPointers.get(src) + imm.getAsLong());
                } else if (registers.containsKey(src)) {
                    registers.put(dest, (registers.get(src) + imm.getAsLong()) & 0xFFFFFFFFL);
                }
            }
        }
    }

    private void handleArmSub(List<String> ops, Map<String, Long> registers, Map<String, Long> stackPointers) {
        if (ops.size() == 2) {
            String dest = normalizeReg(ops.get(0));
            OptionalLong imm = parseImmediate(ops.get(1));
            if (imm.isPresent()) {
                if (stackPointers.containsKey(dest)) {
                    stackPointers.put(dest, stackPointers.get(dest) - imm.getAsLong());
                } else if (registers.containsKey(dest)) {
                    registers.put(dest, (registers.get(dest) - imm.getAsLong()) & 0xFFFFFFFFL);
                }
            }
        } else if (ops.size() >= 3) {
            String dest = normalizeReg(ops.get(0));
            String src = normalizeReg(ops.get(1));
            OptionalLong imm = parseImmediate(ops.get(2));
            if (imm.isPresent()) {
                if (stackPointers.containsKey(src)) {
                    stackPointers.put(dest, stackPointers.get(src) - imm.getAsLong());
                } else if (registers.containsKey(src)) {
                    registers.put(dest, (registers.get(src) - imm.getAsLong()) & 0xFFFFFFFFL);
                }
            }
        }
    }

    private void handleArmStore(
            long addr,
            int idx,
            List<String> ops,
            int sizeBytes,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        if (ops.size() < 2) {
            return;
        }
        String srcReg = normalizeReg(ops.get(0));
        Long val = registers.get(srcReg);
        if (val == null) {
            return;
        }

        MemTarget target = parseBracketMem(ops.get(1));
        if (target != null && stackPointers.containsKey(target.baseReg)) {
            long effectiveOffset = stackPointers.get(target.baseReg) + target.offset;
            writeStackBytes(stackMemory, effectiveOffset, val, sizeBytes, addr, idx);
        }
    }

    private void processRiscvInstruction(
            StackInstruction instr,
            int idx,
            String mnem,
            List<String> ops,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        // Zero register always 0
        registers.put("zero", 0L);
        registers.put("x0", 0L);

        if (mnem.equals("li") || mnem.equals("c.li")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                parseImmediate(ops.get(1)).ifPresent(val -> registers.put(dest, val & 0xFFFFFFFFL));
            }
            return;
        }

        if (mnem.equals("lui")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                parseImmediate(ops.get(1)).ifPresent(val -> registers.put(dest, ((val & 0xFFFFF) << 12) & 0xFFFFFFFFL));
            }
            return;
        }

        if (mnem.equals("addi")) {
            if (ops.size() >= 3) {
                String dest = normalizeReg(ops.get(0));
                String src = normalizeReg(ops.get(1));
                OptionalLong imm = parseImmediate(ops.get(2));
                if (imm.isPresent()) {
                    if (src.equals("zero") || src.equals("x0")) {
                        registers.put(dest, imm.getAsLong() & 0xFFFFFFFFL);
                    } else if (stackPointers.containsKey(src)) {
                        stackPointers.put(dest, stackPointers.get(src) + imm.getAsLong());
                    } else if (registers.containsKey(src)) {
                        registers.put(dest, (registers.get(src) + imm.getAsLong()) & 0xFFFFFFFFL);
                    }
                }
            }
            return;
        }

        if (mnem.equals("mv")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                String src = normalizeReg(ops.get(1));
                if (stackPointers.containsKey(src)) {
                    stackPointers.put(dest, stackPointers.get(src));
                } else if (registers.containsKey(src)) {
                    registers.put(dest, registers.get(src));
                }
            }
            return;
        }

        if (mnem.equals("sb") || mnem.equals("c.sb")) {
            handleRiscvStore(instr.address(), idx, ops, 1, registers, stackPointers, stackMemory);
        } else if (mnem.equals("sh") || mnem.equals("c.sh")) {
            handleRiscvStore(instr.address(), idx, ops, 2, registers, stackPointers, stackMemory);
        } else if (mnem.equals("sw") || mnem.equals("c.sw") || mnem.equals("c.swsp")) {
            handleRiscvStore(instr.address(), idx, ops, 4, registers, stackPointers, stackMemory);
        }
    }

    private void handleRiscvStore(
            long addr,
            int idx,
            List<String> ops,
            int sizeBytes,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        if (ops.size() < 2) {
            return;
        }
        String srcReg = normalizeReg(ops.get(0));
        Long val = registers.get(srcReg);
        if (val == null) {
            return;
        }

        MemTarget target = parseParenMem(ops.get(1));
        if (target != null && stackPointers.containsKey(target.baseReg)) {
            long effectiveOffset = stackPointers.get(target.baseReg) + target.offset;
            writeStackBytes(stackMemory, effectiveOffset, val, sizeBytes, addr, idx);
        }
    }

    private void processXtensaInstruction(
            StackInstruction instr,
            int idx,
            String mnem,
            List<String> ops,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        if (mnem.equals("movi") || mnem.equals("movi.n")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                parseImmediate(ops.get(1)).ifPresent(val -> registers.put(dest, val & 0xFFFFFFFFL));
            }
            return;
        }

        if (mnem.equals("mov") || mnem.equals("mov.n")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                String src = normalizeReg(ops.get(1));
                if (stackPointers.containsKey(src)) {
                    stackPointers.put(dest, stackPointers.get(src));
                } else if (registers.containsKey(src)) {
                    registers.put(dest, registers.get(src));
                }
            }
            return;
        }

        if (mnem.equals("addi") || mnem.equals("addi.n") || mnem.equals("addmi")) {
            if (ops.size() >= 3) {
                String dest = normalizeReg(ops.get(0));
                String src = normalizeReg(ops.get(1));
                OptionalLong imm = parseImmediate(ops.get(2));
                if (imm.isPresent()) {
                    if (stackPointers.containsKey(src)) {
                        stackPointers.put(dest, stackPointers.get(src) + imm.getAsLong());
                    } else if (registers.containsKey(src)) {
                        registers.put(dest, (registers.get(src) + imm.getAsLong()) & 0xFFFFFFFFL);
                    }
                }
            }
            return;
        }

        if (mnem.equals("l32r")) {
            if (ops.size() >= 2) {
                String dest = normalizeReg(ops.get(0));
                parseImmediate(ops.get(1)).ifPresent(val -> registers.put(dest, val & 0xFFFFFFFFL));
            }
            return;
        }

        if (mnem.equals("s8i")) {
            handleXtensaStore(instr.address(), idx, ops, 1, registers, stackPointers, stackMemory);
        } else if (mnem.equals("s16i")) {
            handleXtensaStore(instr.address(), idx, ops, 2, registers, stackPointers, stackMemory);
        } else if (mnem.equals("s32i") || mnem.equals("s32i.n")) {
            handleXtensaStore(instr.address(), idx, ops, 4, registers, stackPointers, stackMemory);
        }
    }

    private void handleXtensaStore(
            long addr,
            int idx,
            List<String> ops,
            int sizeBytes,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        if (ops.size() < 2) {
            return;
        }
        String srcReg = normalizeReg(ops.get(0));
        Long val = registers.get(srcReg);
        if (val == null) {
            return;
        }

        MemTarget target;
        if (ops.size() >= 3) {
            String base = normalizeReg(ops.get(1));
            long offset = parseImmediate(ops.get(2)).orElse(0L);
            target = new MemTarget(base, offset);
        } else {
            target = parseParenMem(ops.get(1));
        }

        if (target != null && stackPointers.containsKey(target.baseReg)) {
            long effectiveOffset = stackPointers.get(target.baseReg) + target.offset;
            writeStackBytes(stackMemory, effectiveOffset, val, sizeBytes, addr, idx);
        }
    }

    private void processStm8Instruction(
            StackInstruction instr,
            int idx,
            String mnem,
            List<String> ops,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        String baseMnem = stripCondition(mnem);
        stackPointers.putIfAbsent("sp", 0L);

        // Immediate loads: ld a, #imm; ldw x, #imm; ldw y, #imm
        if ((baseMnem.equals("ld") || baseMnem.equals("ldw")) && ops.size() >= 2) {
            String dest = normalizeReg(ops.get(0));
            OptionalLong imm = parseImmediate(ops.get(1));
            if (imm.isPresent()) {
                long mask = baseMnem.equals("ldw") ? 0xFFFFL : 0xFFL;
                registers.put(dest, imm.getAsLong() & mask);
                return;
            } else {
                String src = normalizeReg(ops.get(1));
                if (registers.containsKey(src)) {
                    registers.put(dest, registers.get(src));
                    return;
                }
            }
        }

        // Direct store to stack: mov (offset, sp), #imm
        if (baseMnem.equals("mov") && ops.size() >= 2) {
            MemTarget target = parseMemTarget(ops.get(0));
            OptionalLong imm = parseImmediate(ops.get(1));
            if (target != null && stackPointers.containsKey(target.baseReg) && imm.isPresent()) {
                long effectiveOffset = stackPointers.get(target.baseReg) + target.offset;
                writeStackBytes(stackMemory, effectiveOffset, imm.getAsLong() & 0xFFL, 1, instr.address(), idx);
                return;
            }
        }

        // Register stores: ld (offset, sp), a or ldw (offset, sp), x
        if ((baseMnem.equals("ld") || baseMnem.equals("ldw")) && ops.size() >= 2) {
            MemTarget target = parseMemTarget(ops.get(0));
            if (target != null && stackPointers.containsKey(target.baseReg)) {
                String srcReg = normalizeReg(ops.get(1));
                Long val = registers.get(srcReg);
                if (val != null) {
                    int size = baseMnem.endsWith("w") ? 2 : 1;
                    long effectiveOffset = stackPointers.get(target.baseReg) + target.offset;
                    writeStackBytes(stackMemory, effectiveOffset, val, size, instr.address(), idx);
                    return;
                }
            }
        }

        // Stack pushes: push #imm; push a; pushw x; pushw y
        if (baseMnem.equals("push") || baseMnem.equals("pushw")) {
            if (!ops.isEmpty()) {
                long currentSp = stackPointers.get("sp");
                int size = baseMnem.equals("pushw") ? 2 : 1;
                OptionalLong imm = parseImmediate(ops.get(0));
                if (imm.isPresent()) {
                    writeStackBytes(stackMemory, currentSp - size, imm.getAsLong(), size, instr.address(), idx);
                    stackPointers.put("sp", currentSp - size);
                } else {
                    String srcReg = normalizeReg(ops.get(0));
                    Long val = registers.get(srcReg);
                    if (val != null) {
                        writeStackBytes(stackMemory, currentSp - size, val, size, instr.address(), idx);
                    }
                    stackPointers.put("sp", currentSp - size);
                }
                return;
            }
        }

        // Stack adjustments: addw sp, #imm / subw sp, #imm
        if (baseMnem.equals("addw") && ops.size() >= 2 && normalizeReg(ops.get(0)).equals("sp")) {
            parseImmediate(ops.get(1)).ifPresent(imm -> stackPointers.put("sp", stackPointers.get("sp") + imm));
            return;
        }
        if (baseMnem.equals("subw") && ops.size() >= 2 && normalizeReg(ops.get(0)).equals("sp")) {
            parseImmediate(ops.get(1)).ifPresent(imm -> stackPointers.put("sp", stackPointers.get("sp") - imm));
            return;
        }
    }

    private void processAvrInstruction(
            StackInstruction instr,
            int idx,
            String mnem,
            List<String> ops,
            Map<String, Long> registers,
            Map<String, Long> stackPointers,
            Map<Long, StackByteRecord> stackMemory) {
        String baseMnem = stripCondition(mnem);
        stackPointers.putIfAbsent("sp", 0L);
        stackPointers.putIfAbsent("y", 0L);

        // Immediate loads: ldi rd, #imm
        if (baseMnem.equals("ldi") && ops.size() >= 2) {
            String dest = normalizeReg(ops.get(0));
            OptionalLong imm = parseImmediate(ops.get(1));
            if (imm.isPresent()) {
                registers.put(dest, imm.getAsLong() & 0xFFL);
                return;
            }
        }

        // Register copies: mov rd, rr / movw rd, rr
        if ((baseMnem.equals("mov") || baseMnem.equals("movw")) && ops.size() >= 2) {
            String dest = normalizeReg(ops.get(0));
            String src = normalizeReg(ops.get(1));
            if (registers.containsKey(src)) {
                registers.put(dest, registers.get(src));
                return;
            }
        }

        // Stack pushes: push rr
        if (baseMnem.equals("push") && !ops.isEmpty()) {
            long currentSp = stackPointers.get("sp");
            OptionalLong imm = parseImmediate(ops.get(0));
            if (imm.isPresent()) {
                writeStackBytes(stackMemory, currentSp - 1, imm.getAsLong() & 0xFFL, 1, instr.address(), idx);
            } else {
                String srcReg = normalizeReg(ops.get(0));
                Long val = registers.get(srcReg);
                if (val != null) {
                    writeStackBytes(stackMemory, currentSp - 1, val & 0xFFL, 1, instr.address(), idx);
                }
            }
            stackPointers.put("sp", currentSp - 1);
            return;
        }

        // Direct / displaced store to Y pointer or SP: std Y+q, rr / st Y, rr
        if ((baseMnem.equals("std") || baseMnem.equals("st")) && ops.size() >= 2) {
            MemTarget target = parseMemTarget(ops.get(0));
            if (target != null && stackPointers.containsKey(target.baseReg)) {
                String srcReg = normalizeReg(ops.get(1));
                Long val = registers.get(srcReg);
                if (val == null) {
                    OptionalLong imm = parseImmediate(ops.get(1));
                    if (imm.isPresent()) {
                        val = imm.getAsLong();
                    }
                }
                if (val != null) {
                    long effectiveOffset = stackPointers.get(target.baseReg) + target.offset;
                    writeStackBytes(stackMemory, effectiveOffset, val & 0xFFL, 1, instr.address(), idx);
                    return;
                }
            }
        }

        // Pointer adjustments: sbiw Y, imm / adiw Y, imm
        if ((baseMnem.equals("sbiw") || baseMnem.equals("adiw")) && ops.size() >= 2) {
            String reg = normalizeReg(ops.get(0));
            if (stackPointers.containsKey(reg)) {
                OptionalLong imm = parseImmediate(ops.get(1));
                if (imm.isPresent()) {
                    long delta = baseMnem.equals("sbiw") ? -imm.getAsLong() : imm.getAsLong();
                    stackPointers.put(reg, stackPointers.get(reg) + delta);
                }
            }
        }
    }

    private void writeStackBytes(
            Map<Long, StackByteRecord> stackMemory,
            long baseOffset,
            long value,
            int sizeBytes,
            long instrAddr,
            int instrIdx) {
        for (int i = 0; i < sizeBytes; i++) {
            byte b = (byte) ((value >> (i * 8)) & 0xFF);
            stackMemory.put(baseOffset + i, new StackByteRecord(b, instrAddr, instrIdx));
        }
    }

    private List<RecoveredStackString> reconstructStrings(
            long functionAddress,
            Map<Long, StackByteRecord> stackMemory) {
        if (stackMemory.isEmpty()) {
            return List.of();
        }

        List<Long> offsets = new ArrayList<>(stackMemory.keySet());
        Collections.sort(offsets);

        List<RecoveredStackString> results = new ArrayList<>();
        int i = 0;

        while (i < offsets.size()) {
            // Find contiguous run of stack offsets
            int startIdx = i;
            long runStart = offsets.get(i);
            while (i + 1 < offsets.size() && offsets.get(i + 1) == offsets.get(i) + 1) {
                i++;
            }
            int runLength = i - startIdx + 1;
            long runEnd = offsets.get(i);

            byte[] runBytes = new byte[runLength];
            for (int k = 0; k < runLength; k++) {
                runBytes[k] = stackMemory.get(runStart + k).value();
            }

            extractStringsFromRun(functionAddress, runStart, runBytes, stackMemory, results);
            i++;
        }

        return List.copyOf(results);
    }

    private void extractStringsFromRun(
            long functionAddress,
            long runStartOffset,
            byte[] bytes,
            Map<Long, StackByteRecord> stackMemory,
            List<RecoveredStackString> results) {
        int idx = 0;
        while (idx < bytes.length) {
            int strStart = idx;
            StringBuilder sb = new StringBuilder();
            boolean nullTerminated = false;

            while (idx < bytes.length) {
                int b = bytes[idx] & 0xFF;
                if (b == 0x00) {
                    nullTerminated = true;
                    idx++;
                    break;
                }
                if (isPrintableAscii(b)) {
                    sb.append((char) b);
                    idx++;
                } else {
                    break;
                }
            }

            int len = sb.length();
            if (len >= 4) {
                String content = sb.toString();
                StringConfidence confidence = determineStackConfidence(content, nullTerminated);
                long stackOffset = runStartOffset + strStart;

                // Compute instruction span
                long minAddr = Long.MAX_VALUE;
                long maxAddr = Long.MIN_VALUE;
                Set<Long> instrs = new HashSet<>();

                int totalBytes = nullTerminated ? len + 1 : len;
                for (int j = 0; j < totalBytes && strStart + j < bytes.length; j++) {
                    StackByteRecord rec = stackMemory.get(stackOffset + j);
                    if (rec != null) {
                        minAddr = Math.min(minAddr, rec.instructionAddress());
                        maxAddr = Math.max(maxAddr, rec.instructionAddress());
                        instrs.add(rec.instructionAddress());
                    }
                }

                if (!instrs.isEmpty()) {
                    results.add(new RecoveredStackString(
                            functionAddress,
                            stackOffset,
                            content,
                            StringEncoding.ASCII,
                            confidence,
                            minAddr,
                            maxAddr,
                            instrs.size()));
                }
            }

            if (idx == strStart) {
                idx++;
            }
        }
    }

    private StringConfidence determineStackConfidence(String content, boolean nullTerminated) {
        if (nullTerminated && (content.length() >= 6 || containsKnownPattern(content))) {
            return StringConfidence.CONFIRMED;
        }
        if (nullTerminated || content.length() >= 8) {
            return StringConfidence.LIKELY;
        }
        return StringConfidence.PLAUSIBLE;
    }

    private boolean containsKnownPattern(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        return lower.contains("flag{") || lower.contains("ctf{")
                || lower.startsWith("http://") || lower.startsWith("https://")
                || lower.contains("key") || lower.contains("pass");
    }

    private record MemTarget(String baseReg, long offset) { }

    private static MemTarget parseBracketMem(String operand) {
        String trimmed = operand.trim();
        if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) {
            return null;
        }
        String inside = trimmed.substring(1, trimmed.length() - 1).trim();
        String[] parts = inside.split(",");
        String base = normalizeReg(parts[0].trim());
        long offset = 0;
        if (parts.length > 1) {
            offset = parseImmediate(parts[1].trim()).orElse(0L);
        }
        return new MemTarget(base, offset);
    }

    private static MemTarget parseParenMem(String operand) {
        String trimmed = operand.trim();
        int openParen = trimmed.indexOf('(');
        int closeParen = trimmed.indexOf(')');
        if (openParen < 0 || closeParen < openParen) {
            return null;
        }
        String offsetPart = trimmed.substring(0, openParen).trim();
        String basePart = trimmed.substring(openParen + 1, closeParen).trim();

        long offset = parseImmediate(offsetPart).orElse(0L);
        return new MemTarget(normalizeReg(basePart), offset);
    }

    private static MemTarget parseMemTarget(String operand) {
        if (operand == null || operand.isBlank()) {
            return null;
        }
        MemTarget bracket = parseBracketMem(operand);
        if (bracket != null) {
            return bracket;
        }
        MemTarget paren = parseParenMem(operand);
        if (paren != null) {
            return paren;
        }
        String trimmed = operand.trim();
        if (trimmed.startsWith("(") && trimmed.endsWith(")")) {
            String inside = trimmed.substring(1, trimmed.length() - 1).trim();
            String[] parts = inside.split(",");
            if (parts.length == 2) {
                OptionalLong imm1 = parseImmediate(parts[0].trim());
                if (imm1.isPresent()) {
                    return new MemTarget(normalizeReg(parts[1].trim()), imm1.getAsLong());
                }
                OptionalLong imm2 = parseImmediate(parts[1].trim());
                if (imm2.isPresent()) {
                    return new MemTarget(normalizeReg(parts[0].trim()), imm2.getAsLong());
                }
            } else if (parts.length == 1) {
                return new MemTarget(normalizeReg(parts[0].trim()), 0L);
            }
        }
        if (trimmed.contains("+") && !trimmed.startsWith("[")) {
            String[] parts = trimmed.split("\\+");
            if (parts.length == 2) {
                OptionalLong imm = parseImmediate(parts[1].trim());
                if (imm.isPresent()) {
                    return new MemTarget(normalizeReg(parts[0].trim()), imm.getAsLong());
                }
            }
        }
        if (trimmed.equalsIgnoreCase("y") || trimmed.equalsIgnoreCase("z") || trimmed.equalsIgnoreCase("x")) {
            return new MemTarget(normalizeReg(trimmed), 0L);
        }
        return null;
    }

    private static OptionalLong parseImmediate(String token) {
        if (token == null || token.isBlank()) {
            return OptionalLong.empty();
        }
        String s = token.trim();
        if (s.startsWith("#") || s.startsWith("=")) {
            s = s.substring(1).trim();
        }
        if (s.startsWith("+")) {
            s = s.substring(1).trim();
        }
        if (s.startsWith("'") && s.endsWith("'") && s.length() == 3) {
            return OptionalLong.of(s.charAt(1));
        }

        try {
            boolean negative = false;
            if (s.startsWith("-")) {
                negative = true;
                s = s.substring(1).trim();
            }
            long val;
            if (s.startsWith("0x") || s.startsWith("0X")) {
                val = Long.parseUnsignedLong(s.substring(2), 16);
            } else {
                val = Long.parseLong(s);
            }
            return OptionalLong.of(negative ? -val : val);
        } catch (NumberFormatException ignored) {
            return OptionalLong.empty();
        }
    }

    private static String stripCondition(String mnem) {
        int dot = mnem.indexOf('.');
        String base = dot >= 0 ? mnem.substring(0, dot) : mnem;
        return base.toLowerCase(Locale.ROOT);
    }

    private static String normalizeReg(String reg) {
        return reg.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean isPrintableAscii(int b) {
        return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\r' || b == '\n';
    }
}
