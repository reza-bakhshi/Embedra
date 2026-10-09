package io.github.rezabakhshi.embedra.ghidra.plugins;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import io.github.rezabakhshi.embedra.analyzers.plugins.PluginResourceBudget;
import io.github.rezabakhshi.embedra.analyzers.plugins.PluginScanContext;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.analyzers.strings.StringProvenance;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Extracts pure {@link PluginScanContext} snapshots from a Ghidra {@link Program} (AN-009).
 */
public final class GhidraScannerPluginExtractor {

    private GhidraScannerPluginExtractor() {
    }

    /**
     * Extracts memory, strings, and metadata from the given program into a bounded scan context.
     */
    public static PluginScanContext extract(
            Program program,
            PluginResourceBudget budget,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(program, "program must not be null");
        limits = limits != null ? limits : ParserLimits.defaults();
        budget = budget != null ? budget : PluginResourceBudget.defaults();
        token = token != null ? token : CancellationToken.none();

        token.throwIfCancellationRequested();

        // 1. Extract memory bytes
        byte[] data = extractMemoryBytes(program, limits, token);
        long baseAddress = 0L;
        if (program.getMemory() != null && program.getMemory().getMinAddress() != null) {
            baseAddress = program.getMemory().getMinAddress().getOffset();
        }

        // 2. Extract defined strings
        List<ExtractedString> strings = extractDefinedStrings(program, limits, token);

        // 3. Extract metadata
        Map<String, String> metadata = extractMetadata(program);

        // 4. Resolve platform
        String platform = resolvePlatform(program);

        return new PluginScanContext(data, baseAddress, strings, metadata, platform, budget, token);
    }

    private static byte[] extractMemoryBytes(
            Program program,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        if (program.getMemory() == null) {
            return new byte[0];
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long totalRead = 0;

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            token.throwIfCancellationRequested();
            if (!block.isInitialized() || block.getSize() <= 0) {
                continue;
            }

            long toRead = Math.min(block.getSize(), limits.maxInputBytes() - totalRead);
            if (toRead <= 0) {
                break;
            }

            byte[] buf = new byte[(int) toRead];
            try {
                int read = block.getBytes(block.getStart(), buf);
                if (read > 0) {
                    out.write(buf, 0, read);
                    totalRead += read;
                }
            } catch (Exception ignored) {
                // Safely proceed on unreadable block
            }
        }

        return out.toByteArray();
    }

    private static List<ExtractedString> extractDefinedStrings(
            Program program,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        if (program.getListing() == null) {
            return List.of();
        }

        List<ExtractedString> result = new ArrayList<>();
        DataIterator iterator = program.getListing().getDefinedData(true);
        int count = 0;

        while (iterator.hasNext() && count < limits.maxObjects()) {
            token.throwIfCancellationRequested();
            Data d = iterator.next();
            if (d.hasStringValue()) {
                Object val = d.getValue();
                if (val instanceof String s && !s.isBlank()) {
                    long addr = d.getAddress().getOffset();
                    result.add(new ExtractedString(
                            addr,
                            s.length(),
                            StringEncoding.ASCII,
                            s,
                            StringConfidence.CONFIRMED,
                            StringProvenance.STATIC_LITERAL,
                            true
                    ));
                    count++;
                }
            }
        }

        return Collections.unmodifiableList(result);
    }

    private static Map<String, String> extractMetadata(Program program) {
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("Program Name", program.getName());
        if (program.getLanguageID() != null) {
            meta.put("Language ID", program.getLanguageID().getIdAsString());
        }
        if (program.getCompilerSpec() != null && program.getCompilerSpec().getCompilerSpecID() != null) {
            meta.put("Compiler Spec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        }
        return Collections.unmodifiableMap(meta);
    }

    private static String resolvePlatform(Program program) {
        if (program.getLanguageID() == null) {
            return "GENERIC";
        }
        String lang = program.getLanguageID().getIdAsString();
        if (lang.contains("ARM")) {
            return "ARM";
        }
        if (lang.contains("RISCV")) {
            return "RISCV";
        }
        if (lang.contains("Xtensa")) {
            return "XTENSA";
        }
        return "GENERIC";
    }
}
