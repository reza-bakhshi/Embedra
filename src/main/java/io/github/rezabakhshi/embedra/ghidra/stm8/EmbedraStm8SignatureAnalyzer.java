package io.github.rezabakhshi.embedra.ghidra.stm8;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.stm8.Stm8FunctionBytes;
import io.github.rezabakhshi.embedra.analyzers.stm8.Stm8LibrarySignature;
import io.github.rezabakhshi.embedra.analyzers.stm8.Stm8SignatureContext;
import io.github.rezabakhshi.embedra.analyzers.stm8.Stm8SignatureMatch;
import io.github.rezabakhshi.embedra.analyzers.stm8.Stm8SignatureMatchReport;
import io.github.rezabakhshi.embedra.analyzers.stm8.Stm8SignatureMatcher;
import io.github.rezabakhshi.embedra.analyzers.stm8.Stm8SignaturePack;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Ghidra analyzer identifying STM8 Standard Peripheral Library (SPL) and open-source compiler
 * runtime routines (SDCC, Cosmic) using pure byte-pattern constraints (STM8-009).
 */
public final class EmbedraStm8SignatureAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra STM8 SPL & Runtime Signatures";

    public static final String DESCRIPTION = "Applies Standard Peripheral Library (SPL) routines and "
            + "compiler runtime (SDCC, Cosmic) signatures to STM8 firmware images";

    public EmbedraStm8SignatureAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        if (program == null || program.getListing() == null || program.getMemory() == null) {
            return false;
        }
        String langId = program.getLanguageID().getIdAsString().toUpperCase(Locale.ROOT);
        String proc = program.getLanguage().getProcessor().toString().toUpperCase(Locale.ROOT);
        return langId.contains("STM8") || proc.contains("STM8");
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

        // Retrieve recorded options
        var options = program.getOptions(Stm8FirmwareMapper.OPTIONS_CATEGORY);
        String exactPart = options.getString("Exact Part", "STM8_GENERIC");
        String family = options.getString("Family", "STM8");
        String compiler = options.getString("Compiler", "ANY");

        List<Stm8FunctionBytes> functionBytesList = new ArrayList<>();
        var functionIter = program.getFunctionManager().getFunctions(set, true);
        while (functionIter.hasNext()) {
            monitor.checkCancelled();
            Function func = functionIter.next();
            Address entry = func.getEntryPoint();
            byte[] bytes = new byte[64];
            int read = 0;
            try {
                read = program.getMemory().getBytes(entry, bytes);
            } catch (Exception ignored) {
            }
            if (read >= 8) {
                byte[] trimmed = new byte[read];
                System.arraycopy(bytes, 0, trimmed, 0, read);
                functionBytesList.add(new Stm8FunctionBytes(entry.getOffset(), trimmed));
            }
        }

        if (functionBytesList.isEmpty()) {
            return true;
        }

        Stm8SignatureContext context = new Stm8SignatureContext(
                exactPart,
                family,
                Optional.of(compiler),
                Optional.of("-Os"),
                functionBytesList);

        Stm8SignaturePack pack = Stm8SignaturePack.builtin();
        Stm8SignatureMatchReport report;
        try {
            report = Stm8SignatureMatcher.match(context, pack, limits, token);
        } catch (Exception e) {
            log.appendMsg(NAME, "Signature matching failed: " + e.getMessage());
            return false;
        }

        if (report.matches().isEmpty()) {
            return true;
        }

        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply Embedra STM8 signatures")) {
            for (Stm8SignatureMatch match : report.matches()) {
                monitor.checkCancelled();
                Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(match.address());
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) {
                    try {
                        func.setName(match.functionName(), SourceType.IMPORTED);
                    } catch (Exception ignored) {
                    }
                } else {
                    try {
                        program.getSymbolTable().createLabel(addr, match.functionName(), SourceType.IMPORTED);
                    } catch (Exception ignored) {
                    }
                }

                try {
                    program.getListing().setComment(
                            addr,
                            CommentType.PLATE,
                            String.format("Embedra STM8 Signature Match: %s (%s, confidence %s)\nPack: %s",
                                    match.functionName(), match.signatureId(), match.confidence(), match.packIdentity())
                    );
                    program.getBookmarkManager().setBookmark(
                            addr,
                            BookmarkType.INFO,
                            "Embedra Signature",
                            match.signatureId() + " -> " + match.functionName()
                    );
                } catch (Exception ignored) {
                }
            }
            transaction.commit();
        }

        log.appendMsg(NAME, String.format(
                "Applied %d STM8 signatures (scanned %d candidate functions)",
                report.matches().size(), report.functionsScanned()));

        return true;
    }
}
