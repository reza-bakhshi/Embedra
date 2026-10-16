package io.github.rezabakhshi.embedra.ghidra.leads;

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
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLeadsReport;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.ComparisonLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.DebugCommandLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.DebugCommandLeadScanner.CommandTableEntry;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.OtaLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.SecurityLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.MultiEncodingStringScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.StringScanOptions;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Ghidra analyzer for candidate password/token comparisons, hidden commands,
 * debug shells, OTA endpoints, and authorization branches (AN-005).
 */
public final class EmbedraSecurityLeadAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra Security Leads Discovery";

    public static final String DESCRIPTION = "Detects candidate password/token comparisons, hidden commands, "
            + "debug shells, OTA endpoints, and authorization branches as ranked leads (AN-005)";

    private static final String OPT_ENABLE_COMPARISONS = "Enable Password/Token Comparison Recovery";

    private static final String OPT_ENABLE_COMMANDS = "Enable Debug Command & Shell Recovery";

    private static final String OPT_ENABLE_OTA = "Enable OTA Endpoint Recovery";

    private static final String OPT_SCAN_DEPTH = "Scan Window Depth";

    public EmbedraSecurityLeadAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.DATA_ANALYSIS.after().after().after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null && program.getListing() != null && program.getMemory() != null;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPT_ENABLE_COMPARISONS, true, null,
                "Enable candidate password, token, and PIN comparison recovery.");
        options.registerOption(OPT_ENABLE_COMMANDS, true, null,
                "Enable candidate hidden/debug command tables and interactive shell detection.");
        options.registerOption(OPT_ENABLE_OTA, true, null,
                "Enable candidate OTA firmware update endpoint and handler detection.");
        options.registerOption(OPT_SCAN_DEPTH, 32, null,
                "Maximum backward instruction scan depth for argument resolution.");
    }

    @Override
    public boolean added(
            Program program,
            AddressSetView set,
            TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        monitor.checkCancelled();

        InstructionArch arch = detectArchitecture(program);
        ParserLimits limits = ParserLimits.defaults();
        CancellationToken token = monitor::isCancelled;

        int depth = program.getOptions(NAME).getInt(OPT_SCAN_DEPTH, 32);

        // 1. Build string dictionary
        Map<Long, String> stringTable = buildStringDictionary(program, limits, token);

        // 2. Build symbol map
        Map<Long, String> symbolMap = buildSymbolMap(program);

        // 3. Scan command table entries from initialized memory
        List<CommandTableEntry> commandTables = scanCommandTables(program, stringTable, limits, token);

        // 4. Extract function disassemblies
        Map<Long, List<StackInstruction>> functions = new HashMap<>();
        if (arch != null) {
            var funcIter = program.getFunctionManager().getFunctions(set, true);
            while (funcIter.hasNext()) {
                monitor.checkCancelled();
                Function func = funcIter.next();
                long funcAddr = func.getEntryPoint().getOffset();

                List<StackInstruction> instrs = new ArrayList<>();
                InstructionIterator instrIter = program.getListing().getInstructions(func.getBody(), true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    List<String> ops = new ArrayList<>();
                    for (int i = 0; i < instr.getNumOperands(); i++) {
                        ops.add(instr.getDefaultOperandRepresentation(i));
                    }
                    instrs.add(new StackInstruction(
                            instr.getAddress().getOffset(),
                            instr.getMnemonicString(),
                            ops,
                            arch));
                }
                if (!instrs.isEmpty()) {
                    functions.put(funcAddr, instrs);
                }
            }
        }

        // 5. Run unified security lead scan
        SecurityLeadScanner scanner = new SecurityLeadScanner(
                new ComparisonLeadScanner(depth),
                new DebugCommandLeadScanner(),
                new OtaLeadScanner());

        try {
            SecurityLeadsReport leadsReport = scanner.scanAll(
                    functions,
                    stringTable,
                    symbolMap,
                    commandTables,
                    arch,
                    limits,
                    token);

            // 6. Apply annotations transactionally
            GhidraSecurityLeadApplicationReport appReport = GhidraSecurityLeadApplicator.apply(
                    program,
                    leadsReport,
                    monitor);

            log.appendMsg(NAME, String.format(
                    "Discovered %d candidate security leads (Comparisons: %d, Commands: %d, "
                            + "Shells: %d, OTA: %d, Auth Branches: %d, High Confidence: %d)",
                    appReport.totalLeads(),
                    appReport.passwordComparisons(),
                    appReport.debugCommands(),
                    appReport.debugShells(),
                    appReport.otaEndpoints(),
                    appReport.authorizationBranches(),
                    appReport.highConfidenceLeads()));

        } catch (Exception e) {
            log.appendMsg(NAME, "Lead analysis completed with warning: " + e.getMessage());
        }

        return true;
    }

    private static InstructionArch detectArchitecture(Program program) {
        String proc = program.getLanguage().getProcessor().toString().toLowerCase(Locale.ROOT);
        if (proc.contains("arm")) {
            return InstructionArch.ARM_THUMB;
        }
        if (proc.contains("riscv")) {
            return InstructionArch.RISCV32;
        }
        if (proc.contains("xtensa")) {
            return InstructionArch.XTENSA;
        }
        if (proc.contains("stm8")
                || program.getLanguageID().getIdAsString().toLowerCase(Locale.ROOT).contains("stm8")) {
            return InstructionArch.STM8;
        }
        if (proc.contains("avr")
                || program.getLanguageID().getIdAsString().toLowerCase(Locale.ROOT).contains("avr")) {
            return InstructionArch.AVR8;
        }
        return null;
    }

    private static Map<Long, String> buildStringDictionary(
            Program program,
            ParserLimits limits,
            CancellationToken token) {
        Map<Long, String> map = new HashMap<>();

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

        MultiEncodingStringScanner rawScanner = new MultiEncodingStringScanner();
        StringScanOptions scanOptions = StringScanOptions.defaults();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (token.isCancellationRequested()) {
                break;
            }
            if (!block.isInitialized() || block.getSize() > limits.maxInputBytes()) {
                continue;
            }

            try {
                byte[] bytes = new byte[(int) Math.min(block.getSize(), limits.maxInputBytes())];
                block.getBytes(block.getStart(), bytes);

                List<ExtractedString> extracted = rawScanner.scan(
                        bytes, block.getStart().getOffset(), scanOptions, limits, token);
                for (ExtractedString es : extracted) {
                    long addr = es.offset();
                    map.putIfAbsent(addr, es.content());
                }
            } catch (Exception ignored) {
                // fall through
            }
        }

        return map;
    }

    private static Map<Long, String> buildSymbolMap(Program program) {
        Map<Long, String> map = new HashMap<>();
        for (Symbol sym : program.getSymbolTable().getAllSymbols(true)) {
            if (sym.getName() != null && !sym.getName().isBlank()) {
                map.put(sym.getAddress().getOffset(), sym.getName());
            }
        }
        return map;
    }

    private static List<CommandTableEntry> scanCommandTables(
            Program program,
            Map<Long, String> stringTable,
            ParserLimits limits,
            CancellationToken token) {
        List<CommandTableEntry> entries = new ArrayList<>();
        ByteOrder order = program.getLanguage().isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int defaultPtrSize = program.getDefaultPointerSize();
        boolean isThumb = detectArchitecture(program) == InstructionArch.ARM_THUMB;

        // Support pointer awareness for 16-bit (2), 24-bit (3), and 32-bit (4) pointers
        List<Integer> candidatePtrSizes = new ArrayList<>();
        if (defaultPtrSize <= 2) {
            candidatePtrSizes.add(2);
            candidatePtrSizes.add(3);
        } else if (defaultPtrSize == 3) {
            candidatePtrSizes.add(3);
            candidatePtrSizes.add(2);
        } else {
            candidatePtrSizes.add(4);
        }

        for (int ptrSize : candidatePtrSizes) {
            int entrySize = ptrSize * 2;
            int step = ptrSize;

            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (token.isCancellationRequested() || entries.size() >= limits.maxObjects()) {
                    break;
                }
                if (!block.isInitialized() || block.isExecute() || block.getSize() < entrySize) {
                    continue;
                }

                int size = (int) Math.min(block.getSize(), 65536);
                byte[] bytes = new byte[size];
                try {
                    block.getBytes(block.getStart(), bytes);
                } catch (Exception e) {
                    continue;
                }

                ByteBuffer buffer = ByteBuffer.wrap(bytes).order(order);
                for (int offset = 0; offset <= size - entrySize; offset += step) {
                    if (token.isCancellationRequested() || entries.size() >= limits.maxObjects()) {
                        break;
                    }

                    long strPtr = readPointer(buffer, offset, ptrSize, order);
                    long fnPtr = readPointer(buffer, offset + ptrSize, ptrSize, order);

                    // Clear odd bit only on ARM Thumb
                    long codeAddr = isThumb ? (fnPtr & ~1L) : fnPtr;

                    if (stringTable.containsKey(strPtr)) {
                        String cmdStr = stringTable.get(strPtr).trim();
                        if (cmdStr.length() >= 2 && cmdStr.length() <= 32 && isExecutableAddress(program, codeAddr)) {
                            long tableAddr = block.getStart().getOffset() + offset;
                            entries.add(new CommandTableEntry(tableAddr, cmdStr, codeAddr, ""));
                        }
                    }
                }
            }
            if (!entries.isEmpty()) {
                break;
            }
        }

        return entries;
    }

    private static long readPointer(ByteBuffer buffer, int offset, int ptrSize, ByteOrder order) {
        if (ptrSize == 2) {
            return Short.toUnsignedLong(buffer.getShort(offset));
        } else if (ptrSize == 3) {
            int b0 = buffer.get(offset) & 0xFF;
            int b1 = buffer.get(offset + 1) & 0xFF;
            int b2 = buffer.get(offset + 2) & 0xFF;
            if (order == ByteOrder.BIG_ENDIAN) {
                return ((long) b0 << 16) | ((long) b1 << 8) | b2;
            } else {
                return (long) b0 | ((long) b1 << 8) | ((long) b2 << 16);
            }
        } else {
            return Integer.toUnsignedLong(buffer.getInt(offset));
        }
    }

    private static boolean isExecutableAddress(Program program, long addr) {
        try {
            var ghidraAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
            MemoryBlock block = program.getMemory().getBlock(ghidraAddr);
            return block != null && block.isExecute();
        } catch (Exception e) {
            return false;
        }
    }
}
