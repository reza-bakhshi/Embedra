package io.github.rezabakhshi.embedra.ghidra.logging;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.logging.LoggingCallSite;
import io.github.rezabakhshi.embedra.analyzers.logging.linkage.CallSiteArgumentResolver;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.MultiEncodingStringScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.StringScanOptions;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Ghidra analyzer for automated logging, assert, and panic recovery
 * across ARM, RISC-V, and Xtensa architectures (AN-004).
 */
public final class EmbedraLoggingAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra Logging & Diagnostics Recovery";

    public static final String DESCRIPTION = "Identifies embedded logging, assert, and panic call sites, "
            + "extracts format strings, and resolves arguments across ARM, RISC-V, and Xtensa architectures";

    private static final String OPT_ENABLE_FORMAT_RECOVERY = "Enable Format String Recovery";

    private static final String OPT_ENABLE_ASSERT_RECOVERY = "Enable Assert & Panic Recovery";

    private static final String OPT_SCAN_DEPTH = "Scan Window Depth";

    public EmbedraLoggingAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.DATA_ANALYSIS.after().after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null && program.getListing() != null && program.getMemory() != null;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPT_ENABLE_FORMAT_RECOVERY, true, null,
                "Enable printf/logging format string and call-site recovery.");
        options.registerOption(OPT_ENABLE_ASSERT_RECOVERY, true, null,
                "Enable assert and panic recovery with trap instruction linkage.");
        options.registerOption(OPT_SCAN_DEPTH, 32, null,
                "Maximum backward instruction scan depth for argument register tracking.");
    }

    @Override
    public boolean added(
            Program program,
            AddressSetView set,
            TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        monitor.checkCancelled();

        InstructionArch arch = detectArch(program);
        if (arch == null) {
            // Target architecture is not currently supported for call-site register tracking
            return true;
        }

        ParserLimits limits = ParserLimits.defaults();
        CancellationToken token = monitor::isCancelled;

        int depth = program.getOptions(NAME).getInt(OPT_SCAN_DEPTH, 32);
        CallSiteArgumentResolver resolver = new CallSiteArgumentResolver(depth);

        // 1. Build string dictionary from defined strings and memory scanner
        Map<Long, String> stringTable = buildStringDictionary(program, limits, token);

        // 2. Iterate functions and resolve call sites
        List<LoggingCallSite> allCallSites = new ArrayList<>();
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
                try {
                    List<LoggingCallSite> sites = resolver.resolveCallSites(
                            funcAddr, instructions, stringTable, limits, token);
                    allCallSites.addAll(sites);
                } catch (Exception ignored) {
                    // Gracefully continue with remaining functions
                }
            }
        }

        // 3. Apply annotations
        GhidraLoggingApplicationReport report = GhidraLoggingApplicator.apply(
                program, allCallSites, monitor);

        log.appendMsg(NAME, String.format(
                "Recovered %d diagnostic call sites (Panic: %d, Assert: %d, Error: %d, "
                        + "Warning: %d, Info: %d, Debug: %d)",
                report.totalCallSites(),
                report.panicCount(),
                report.assertCount(),
                report.errorCount(),
                report.warningCount(),
                report.infoCount(),
                report.debugCount()));

        return true;
    }

    private static Map<Long, String> buildStringDictionary(
            Program program,
            ParserLimits limits,
            CancellationToken token) {
        Map<Long, String> map = new HashMap<>();

        // Defined strings in listing
        var dataIter = program.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            if (token.isCancellationRequested()) {
                break;
            }
            Data d = dataIter.next();
            StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
            if (sdi != null && sdi.getStringLength() > 0) {
                String str = sdi.getStringValue();
                if (str != null && !str.isBlank()) {
                    map.put(d.getAddress().getOffset(), str);
                }
            }
        }

        // Scan initialized blocks for any remaining static literal strings
        MultiEncodingStringScanner scanner = new MultiEncodingStringScanner();
        StringScanOptions scanOptions = StringScanOptions.defaults();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (token.isCancellationRequested()) {
                break;
            }
            if (!block.isInitialized() || block.getSize() <= 0) {
                continue;
            }

            try {
                int size = (int) Math.min(block.getSize(), limits.maxInputBytes());
                byte[] bytes = new byte[size];
                block.getBytes(block.getStart(), bytes);

                List<ExtractedString> extracted = scanner.scan(
                        bytes, block.getStart().getOffset(), scanOptions, limits, token);
                for (ExtractedString es : extracted) {
                    map.putIfAbsent(es.offset(), es.content());
                }
            } catch (Exception ignored) {
                // Safely proceed
            }
        }

        return map;
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
