package io.github.rezabakhshi.embedra.ghidra.crypto;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoScanOptions;
import io.github.rezabakhshi.embedra.analyzers.crypto.fusion.CryptoAnalysisPipeline;
import io.github.rezabakhshi.embedra.analyzers.crypto.fusion.CryptoAnalysisReport;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCallSite;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCryptoAnalyzer;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCryptoPlatform;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCryptoReport;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareMemoryAccess;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;

/**
 * Automated Ghidra analyzer for cryptographic constants, tables, candidate keys,
 * library signatures, vendor ROM routines, and hardware crypto accelerators (AN-003, AN-010, AN-013).
 */
public final class EmbedraCryptoAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra Layered Crypto Analysis";

    public static final String DESCRIPTION = "Discovers cryptographic constants, tables, "
            + "algorithms, candidate keys, hardware accelerators, and vendor ROM routines";

    public EmbedraCryptoAnalyzer() {
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

        CryptoAnalysisPipeline pipeline = new CryptoAnalysisPipeline();
        CryptoScanOptions options = CryptoScanOptions.defaults();

        // Collect symbol and function leads for evidence fusion
        List<String> symbolLeads = new ArrayList<>();
        var symIter = program.getSymbolTable().getAllSymbols(true);
        int symCount = 0;
        while (symIter.hasNext() && symCount < 5000) {
            Symbol sym = symIter.next();
            symbolLeads.add(sym.getName());
            symCount++;
        }

        var funcIter = program.getFunctionManager().getFunctions(true);
        int funcCount = 0;
        while (funcIter.hasNext() && funcCount < 2000) {
            Function func = funcIter.next();
            symbolLeads.add(func.getName());
            funcCount++;
        }

        List<CryptoFinding> allFindings = new ArrayList<>();

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

                CryptoAnalysisReport report = pipeline.analyze(
                        bytes,
                        block.getStart().getOffset(),
                        options,
                        symbolLeads,
                        List.of(),
                        limits,
                        token);

                allFindings.addAll(report.findings());
            } catch (io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException e) {
                if (monitor.isCancelled()) {
                    throw new CancelledException();
                }
                log.appendException(e);
            } catch (Exception ignored) {
                // Safely proceed past inaccessible blocks
            }
        }

        // Extract references, writes, and call sites for hardware crypto analysis (AN-010, AN-013)
        if (options.scanHardware()) {
            List<HardwareMemoryAccess> accesses = new ArrayList<>();
            List<HardwareCallSite> callSites = new ArrayList<>();

            var refIter = program.getReferenceManager().getReferenceSourceIterator(set, true);
            int refCount = 0;
            while (refIter.hasNext() && refCount < 10000) {
                monitor.checkCancelled();
                Address source = refIter.next();
                for (Reference ref : program.getReferenceManager().getReferencesFrom(source)) {
                    long target = ref.getToAddress().getOffset();
                    if (ref.getReferenceType().isWrite()) {
                        accesses.add(new HardwareMemoryAccess(
                                source.getOffset(),
                                target,
                                true,
                                resolvedStoreValue(program, source, target)));
                    } else if (ref.getReferenceType().isRead()) {
                        accesses.add(HardwareMemoryAccess.read(source.getOffset(), target));
                    } else if (ref.getReferenceType().isCall()) {
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(ref.getToAddress());
                        String name = symbol != null ? symbol.getName() : "";
                        callSites.add(new HardwareCallSite(
                                source.getOffset(),
                                target,
                                name,
                                List.of()));
                    }
                    refCount++;
                }
            }

            HardwareCryptoAnalyzer hwAnalyzer = new HardwareCryptoAnalyzer();
            HardwareCryptoPlatform hwPlatform = HardwareCryptoPlatform.fromKey(
                    program.getLanguage().getProcessor().toString());
            try {
                HardwareCryptoReport hwReport = hwAnalyzer.analyze(
                        hwPlatform, accesses, callSites, List.of(), limits, token);
                allFindings.addAll(hwReport.findings());
            } catch (Exception ignored) {
                // Safely proceed past hardware inspection failure
            }
        }

        monitor.checkCancelled();
        GhidraCryptoApplicationReport appReport = GhidraCryptoApplicator.apply(program, allFindings, monitor);

        // Aggregate logging only to protect against sensitive secret key leakage (AN-008)
        log.appendMsg(getName(), String.format(
                "Embedra Crypto Analysis discovered %d findings (%d bookmarks, %d comments)",
                appReport.totalFindings(),
                appReport.bookmarksCreated(),
                appReport.commentsCreated()));

        return true;
    }

    private static OptionalLong resolvedStoreValue(Program program, Address source, long target) {
        Instruction instruction = program.getListing().getInstructionAt(source);
        if (instruction == null) {
            return OptionalLong.empty();
        }
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() != PcodeOp.STORE || operation.getNumInputs() < 3) {
                continue;
            }
            Varnode address = operation.getInput(1);
            Varnode value = operation.getInput(2);
            if (address.isConstant() && address.getOffset() == target && value.isConstant()) {
                return OptionalLong.of(value.getOffset());
            }
        }
        return OptionalLong.empty();
    }
}
