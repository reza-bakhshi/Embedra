package io.github.rezabakhshi.embedra.ghidra.atmel;

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
import io.github.rezabakhshi.embedra.analyzers.atmel.AtmelFunctionBytes;
import io.github.rezabakhshi.embedra.analyzers.atmel.AtmelSignatureContext;
import io.github.rezabakhshi.embedra.analyzers.atmel.AtmelSignatureMatch;
import io.github.rezabakhshi.embedra.analyzers.atmel.AtmelSignatureMatchReport;
import io.github.rezabakhshi.embedra.analyzers.atmel.AtmelSignatureMatcher;
import io.github.rezabakhshi.embedra.analyzers.atmel.AtmelSignaturePack;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Ghidra analyzer identifying Atmel/Microchip Arduino core, AVR-libc, Atmel START / ASF,
 * and FreeRTOS routines using byte-pattern matching.
 */
public final class EmbedraAtmelSignatureAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra Atmel / Microchip Signatures";

    public static final String DESCRIPTION = "Applies Arduino core, AVR-libc, Atmel START / ASF, "
            + "and FreeRTOS routine signatures to Atmel and Microchip firmware images";

    public EmbedraAtmelSignatureAnalyzer() {
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
        boolean isAvr = langId.contains("AVR8") || proc.contains("AVR");
        boolean isArm = (langId.contains("ARM:LE:32") || proc.contains("ARM"));
        if (!isAvr && !isArm) {
            return false;
        }

        var options = program.getOptions(AtmelFirmwareMapper.OPTIONS_CATEGORY);
        String part = options.getString("Target Silicon Part", "");
        if (!part.isEmpty()) {
            return true;
        }
        return isAvr || isArm;
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

        var options = program.getOptions(AtmelFirmwareMapper.OPTIONS_CATEGORY);
        String langId = program.getLanguageID().getIdAsString().toUpperCase(Locale.ROOT);
        boolean isAvr = langId.contains("AVR8")
                || program.getLanguage().getProcessor().toString().toUpperCase(Locale.ROOT).contains("AVR");

        String defaultPart = isAvr ? "ATmega328P" : "SAMD21G18A";
        String defaultSeries = isAvr ? "ATmega" : "SAMD";
        String defaultArch = isAvr ? "AVR8" : "ARM_THUMB";

        String exactPart = options.getString("Target Silicon Part", defaultPart);
        String series = options.getString("Series", defaultSeries);
        String arch = isAvr ? "AVR8" : "ARM_THUMB";

        List<AtmelFunctionBytes> functionBytesList = new ArrayList<>();
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
                functionBytesList.add(new AtmelFunctionBytes(entry.getOffset(), trimmed));
            }
        }

        if (functionBytesList.isEmpty()) {
            return true;
        }

        AtmelSignatureContext context = new AtmelSignatureContext(
                exactPart,
                series,
                arch,
                Optional.of("ANY"),
                Optional.empty(),
                functionBytesList);

        AtmelSignaturePack pack = AtmelSignaturePack.builtin();
        AtmelSignatureMatchReport report;
        try {
            report = AtmelSignatureMatcher.match(context, pack, limits, token);
        } catch (Exception e) {
            log.appendMsg(NAME, "Signature matching failed: " + e.getMessage());
            return false;
        }

        if (report.matches().isEmpty()) {
            return true;
        }

        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply Embedra Atmel signatures")) {
            for (AtmelSignatureMatch match : report.matches()) {
                monitor.checkCancelled();
                Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(match.address());
                if (isAvr && program.getAddressFactory().getAddressSpace("code") != null) {
                    addr = program.getAddressFactory().getAddressSpace("code").getAddress(match.address());
                }
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
                                    "Embedra Atmel Signature Match: %s (%s, subsystem %s, confidence %s)\nPack: %s",
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
                "Applied %d Atmel/Microchip signatures (scanned %d candidate functions)",
                report.matches().size(), report.functionsScanned()));

        return true;
    }
}
