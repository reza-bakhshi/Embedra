package io.github.rezabakhshi.embedra.ghidra.ctf;

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
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityScanner;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfScanOptions;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.MultiEncodingStringScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.StringScanOptions;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackStringRecoveryAnalyzer;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Ghidra analyzer for CTF entities, endpoints, credentials, certificates, UUIDs, blobs, and flags.
 */
public final class EmbedraCtfAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra CTF & Entity Discovery";

    public static final String DESCRIPTION = "Scans endpoints, credentials, certificates, UUIDs, "
            + "encoded blobs, and customizable flags across memory and reconstructed strings";

    public EmbedraCtfAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.DATA_ANALYSIS.after().after());
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
        List<CtfEntity> discoveredEntities = new ArrayList<>();

        MultiEncodingStringScanner stringScanner = new MultiEncodingStringScanner();
        StringScanOptions stringScanOptions = StringScanOptions.defaults();
        CtfEntityScanner entityScanner = new CtfEntityScanner();
        CtfScanOptions entityOptions = CtfScanOptions.defaults();

        // 1. Scan memory blocks for static strings and binary DER certificates
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || block.getSize() <= 0) {
                continue;
            }

            if (set != null && !set.isEmpty() && !set.intersects(block.getStart(), block.getEnd())) {
                continue;
            }

            try {
                int size = (int) Math.min(block.getSize(), limits.maxInputBytes());
                byte[] bytes = new byte[size];
                block.getBytes(block.getStart(), bytes);

                // Scan static strings
                List<ExtractedString> extracted = stringScanner.scan(
                        bytes, block.getStart().getOffset(), stringScanOptions, limits, token);
                staticStrings.addAll(extracted);

                // Scan binary DER certificates
                List<CtfEntity> derCerts = entityScanner.scanBytes(
                        bytes, block.getStart().getOffset(), entityOptions, token);
                discoveredEntities.addAll(derCerts);
            } catch (Exception ignored) {
                // Safely proceed
            }
        }

        // 2. Recover stack strings in functions
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
                InstructionIterator instIter = program.getListing().getInstructions(func.getBody(), true);
                while (instIter.hasNext()) {
                    Instruction inst = instIter.next();
                    List<String> operands = new ArrayList<>();
                    for (int i = 0; i < inst.getNumOperands(); i++) {
                        operands.add(inst.getDefaultOperandRepresentation(i));
                    }
                    instructions.add(new StackInstruction(
                            inst.getAddress().getOffset(),
                            inst.getMnemonicString(),
                            operands,
                            arch
                    ));
                }

                if (!instructions.isEmpty()) {
                    functionMap.put(funcAddr, instructions);
                }
            }

            try {
                stackStrings.addAll(stackAnalyzer.analyzeFunctions(functionMap, limits, token));
            } catch (Exception ignored) {
                // Proceed without stack strings on analysis failure
            }
        }

        // 3. Scan static and stack strings for CTF entities
        try {
            discoveredEntities.addAll(entityScanner.scanStrings(staticStrings, entityOptions, token));
            discoveredEntities.addAll(entityScanner.scanStackStrings(stackStrings, entityOptions, token));
        } catch (Exception ignored) {
            // Proceed with whatever entities were discovered
        }

        // 4. Apply annotations to the Ghidra Program
        GhidraCtfApplicationReport report = GhidraCtfApplicator.apply(program, discoveredEntities, monitor);

        log.appendMsg(NAME, String.format(
                "Embedra CTF Findings: identified %d findings (%d bookmarks, %d comments)",
                report.totalFindings(), report.bookmarksCreated(), report.commentsCreated()));

        return true;
    }

    private static InstructionArch detectArch(Program program) {
        String langId = program.getLanguageID().getIdAsString();
        if (langId.startsWith("ARM:LE:32:") || langId.startsWith("ARM:")) {
            return InstructionArch.ARM_THUMB;
        } else if (langId.contains("RISCV:LE:32")) {
            return InstructionArch.RISCV32;
        } else if (langId.contains("Xtensa")) {
            return InstructionArch.XTENSA;
        }
        return null;
    }
}
