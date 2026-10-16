package io.github.rezabakhshi.embedra.ghidra.nordic;

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
import io.github.rezabakhshi.embedra.analyzers.nordic.NordicFunctionBytes;
import io.github.rezabakhshi.embedra.analyzers.nordic.NordicSignatureContext;
import io.github.rezabakhshi.embedra.analyzers.nordic.NordicSignatureMatch;
import io.github.rezabakhshi.embedra.analyzers.nordic.NordicSignatureMatchReport;
import io.github.rezabakhshi.embedra.analyzers.nordic.NordicSignatureMatcher;
import io.github.rezabakhshi.embedra.analyzers.nordic.NordicSignaturePack;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Ghidra analyzer identifying Nordic Semiconductor nRF5 SDK, nRF Connect SDK (Zephyr),
 * and SoftDevice BLE/Crypto routines using byte-pattern matching (NRF-005, NRF-009).
 */
public final class EmbedraNordicSignatureAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra Nordic SDK & BLE Signatures";

    public static final String DESCRIPTION = "Applies nRF5 SDK, nRF Connect SDK (Zephyr), and SoftDevice "
            + "BLE/Crypto routine signatures to Nordic Semiconductor firmware images";

    public EmbedraNordicSignatureAnalyzer() {
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
        if (!langId.contains("ARM:LE:32") && !proc.contains("ARM")) {
            return false;
        }

        var options = program.getOptions(NordicFirmwareMapper.OPTIONS_CATEGORY);
        String exactPart = options.getString("Exact Part", "");
        return exactPart.toLowerCase(Locale.ROOT).startsWith("nrf") || exactPart.isEmpty();
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
        var options = program.getOptions(NordicFirmwareMapper.OPTIONS_CATEGORY);
        String exactPart = options.getString("Exact Part", "nRF52840-QIAA");
        String series = options.getString("Series", "nRF52");

        List<NordicFunctionBytes> functionBytesList = new ArrayList<>();
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
                functionBytesList.add(new NordicFunctionBytes(entry.getOffset(), trimmed));
            }
        }

        if (functionBytesList.isEmpty()) {
            return true;
        }

        NordicSignatureContext context = new NordicSignatureContext(
                exactPart,
                series,
                Optional.of("ANY"),
                Optional.empty(),
                functionBytesList);

        NordicSignaturePack pack = NordicSignaturePack.builtin();
        NordicSignatureMatchReport report;
        try {
            report = NordicSignatureMatcher.match(context, pack, limits, token);
        } catch (Exception e) {
            log.appendMsg(NAME, "Signature matching failed: " + e.getMessage());
            return false;
        }

        if (report.matches().isEmpty()) {
            return true;
        }

        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply Embedra Nordic signatures")) {
            for (NordicSignatureMatch match : report.matches()) {
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
                            String.format(
                                    "Embedra Nordic Signature Match: %s (%s, subsystem %s, confidence %s)\nPack: %s",
                                    match.functionName(), match.signatureId(), match.subsystem(),
                                    match.confidence(), match.packIdentity())
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
                "Applied %d Nordic signatures (scanned %d candidate functions)",
                report.matches().size(), report.functionsScanned()));

        return true;
    }
}
