package io.github.rezabakhshi.embedra.ghidra.esp;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.esp.EspCryptoCallFact;
import io.github.rezabakhshi.embedra.analyzers.esp.EspHardwareCryptoAnalyzer;
import io.github.rezabakhshi.embedra.analyzers.esp.EspHardwareCryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.esp.EspHardwareCryptoReport;
import io.github.rezabakhshi.embedra.analyzers.esp.EspMemoryAccessFact;
import io.github.rezabakhshi.embedra.analyzers.esp.EspMemoryAccessKind;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.OptionalLong;

/** Ghidra bridge for conservative ESP32-S3 hardware and resolved-API crypto evidence. */
public final class EmbedraEsp32S3CryptoAnalyzer extends AbstractAnalyzer {
    private static final String SVD_OPTIONS = "Embedra ESP32-S3 SVD";

    private static final String RESULTS_OPTIONS = "Embedra ESP32-S3 Crypto Analysis";

    private static final String BOOKMARK_TYPE = "Analysis";

    private static final String BOOKMARK_CATEGORY = "Embedra Crypto";

    public EmbedraEsp32S3CryptoAnalyzer() {
        super("Embedra ESP32-S3 Crypto Evidence",
            "Detects evidence-backed ESP32-S3 hardware crypto and resolved ROM API use",
            AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "espressif.esp32s3.svd".equals(program.getOptions(SVD_OPTIONS)
            .getString("Pack ID", ""));
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        monitor.checkCancelled();
        List<EspMemoryAccessFact> accesses = new ArrayList<>();
        List<EspCryptoCallFact> calls = new ArrayList<>();
        var sourceIterator = program.getReferenceManager().getReferenceSourceIterator(set,
            true);
        while (sourceIterator.hasNext()) {
            monitor.checkCancelled();
            Address source = sourceIterator.next();
            for (Reference reference : program.getReferenceManager().getReferencesFrom(source)) {
                long target = reference.getToAddress().getOffset();
                if (reference.getReferenceType().isWrite()
                    || reference.getReferenceType().isRead()) {
                    EspMemoryAccessKind kind = reference.getReferenceType().isWrite()
                        ? EspMemoryAccessKind.WRITE : EspMemoryAccessKind.READ;
                    accesses.add(new EspMemoryAccessFact(source.getOffset(), target, kind,
                        kind == EspMemoryAccessKind.WRITE
                            ? resolvedStoreValue(program, source, target)
                            : OptionalLong.empty()));
                }
                if (reference.getReferenceType().isCall()) {
                    Symbol symbol = program.getSymbolTable().getPrimarySymbol(
                        reference.getToAddress());
                    if (symbol != null) {
                        calls.add(new EspCryptoCallFact(source.getOffset(), target,
                            symbol.getName(), symbol.getSource().name()));
                    }
                }
            }
        }
        try {
            EspHardwareCryptoReport report = new EspHardwareCryptoAnalyzer().analyze(
                accesses, calls, ParserLimits.defaults(), monitor::isCancelled);
            annotate(program, report);
            recordCoverage(program, report);
            log.appendMsg(getName(), "Recorded " + report.findings().size()
                + " evidence-backed crypto findings; unsupported coverage is stored "
                + "in program options");
            return true;
        }
        catch (DiagnosticException exception) {
            log.appendException(exception);
            return false;
        }
    }

    private static OptionalLong resolvedStoreValue(Program program, Address source,
            long target) {
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

    private static void annotate(Program program, EspHardwareCryptoReport report) {
        for (EspHardwareCryptoFinding finding : report.findings()) {
            Address address = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(finding.address());
            String comment = finding.kind() + ": " + finding.algorithm()
                + " [" + finding.confidence() + "] at 0x"
                + HexFormat.of().toHexDigits(finding.address());
            program.getBookmarkManager().setBookmark(address, BOOKMARK_TYPE,
                BOOKMARK_CATEGORY, comment);
        }
    }

    private static void recordCoverage(Program program, EspHardwareCryptoReport report) {
        var options = program.getOptions(RESULTS_OPTIONS);
        options.setInt("Finding Count", report.findings().size());
        options.setString("Detectors Ran", String.join(",", report.detectorsRan()));
        options.setString("Unsupported Algorithms",
            String.join(",", report.unsupportedAlgorithms()));
        options.setString("Claim Boundary",
            "A peripheral, constant, or entropy region alone is not verified crypto use");
    }
}
