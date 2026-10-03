package io.github.rezabakhshi.embedra.ghidra.strings;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.MultiEncodingStringScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.StringScanOptions;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackStringRecoveryAnalyzer;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Ghidra analyzer for multi-encoding string discovery and stack-constructed string recovery.
 */
public final class EmbedraStringAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra String & Stack-String Recovery";

    public static final String DESCRIPTION = "Scans bounded multi-encoding static strings and "
            + "recovers stack-constructed strings across ARM, RISC-V, and Xtensa architectures";

    public EmbedraStringAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.DATA_ANALYSIS.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null && program.getMemory() != null;
    }

    @Override
    public boolean added(
            Program program,
            AddressSetView set,
            TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        monitor.checkCancelled();

        ParserLimits limits = ParserLimits.defaults();
        CancellationToken token = monitor::isCancelled;

        List<ExtractedString> staticStrings = new ArrayList<>();
        List<RecoveredStackString> stackStrings = new ArrayList<>();

        // 1. Scan static strings in initialized memory blocks
        MultiEncodingStringScanner scanner = new MultiEncodingStringScanner();
        StringScanOptions scanOptions = StringScanOptions.defaults();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || block.getSize() <= 0) {
                continue;
            }

            // Only scan blocks overlapping the requested address set if non-empty
            if (set != null && !set.isEmpty() && !set.intersects(block.getStart(), block.getEnd())) {
                continue;
            }

            try {
                int size = (int) Math.min(block.getSize(), limits.maxInputBytes());
                byte[] bytes = new byte[size];
                block.getBytes(block.getStart(), bytes);

                List<ExtractedString> extracted = scanner.scan(
                        bytes, block.getStart().getOffset(), scanOptions, limits, token);
                staticStrings.addAll(extracted);

                if (staticStrings.size() >= scanOptions.maxStrings()) {
                    break;
                }
            } catch (Exception ignored) {
                // Safely proceed with remaining blocks
            }
        }

        // 2. Recover stack strings in functions if supported architecture
        InstructionArch arch = detectArch(program);
        if (arch != null) {
            StackStringRecoveryAnalyzer stackAnalyzer = new StackStringRecoveryAnalyzer();
            Map<Long, List<StackInstruction>> functionMap = new HashMap<>();

            var functionIter = program.getFunctionManager().getFunctions(set, true);
            while (functionIter.hasNext()) {
                monitor.checkCancelled();
                Function func = functionIter.next();
                long funcAddr = func.getEntryPoint().getOffset();

                List<StackInstruction> instructions = new ArrayList<>();
                InstructionIterator instrIter = program.getListing().getInstructions(func.getBody(), true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    List<String> operands = new ArrayList<>();
                    for (int i = 0; i < instr.getNumOperands(); i++) {
                        operands.add(instr.getDefaultOperandRepresentation(i));
                    }
                    instructions.add(new StackInstruction(
                            instr.getAddress().getOffset(),
                            instr.getMnemonicString(),
                            operands,
                            arch));
                }

                if (!instructions.isEmpty()) {
                    functionMap.put(funcAddr, instructions);
                }
            }

            try {
                stackStrings.addAll(stackAnalyzer.analyzeFunctions(functionMap, limits, token));
            } catch (DiagnosticException ignored) {
                // Safely continue
            }
        }

        // 3. Apply annotations
        GhidraStringApplicationReport report = GhidraStringApplicator.apply(
                program, staticStrings, stackStrings, monitor);

        log.appendMsg(NAME, String.format(
                "Discovered %d static strings and %d stack strings",
                report.staticStringsCount(), report.stackStringsCount()));

        return true;
    }

    private static InstructionArch detectArch(Program program) {
        String langId = program.getLanguageID().getIdAsString();
        if (langId.startsWith("ARM:LE:32:") || langId.startsWith("ARM:")) {
            return InstructionArch.ARM_THUMB;
        }
        if (langId.startsWith("RISCV:LE:32:") || langId.startsWith("RISCV:")) {
            return InstructionArch.RISCV32;
        }
        if (langId.startsWith("Xtensa:LE:32:") || langId.startsWith("Xtensa:")) {
            return InstructionArch.XTENSA;
        }
        return null;
    }
}
