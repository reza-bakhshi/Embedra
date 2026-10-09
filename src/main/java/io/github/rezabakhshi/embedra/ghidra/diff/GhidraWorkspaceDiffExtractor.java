package io.github.rezabakhshi.embedra.ghidra.diff;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import io.github.rezabakhshi.embedra.analyzers.diff.FunctionSnapshot;
import io.github.rezabakhshi.embedra.analyzers.diff.MemoryBlockSnapshot;
import io.github.rezabakhshi.embedra.analyzers.diff.MetadataSnapshot;
import io.github.rezabakhshi.embedra.analyzers.diff.PartitionSnapshot;
import io.github.rezabakhshi.embedra.analyzers.diff.StringSnapshot;
import io.github.rezabakhshi.embedra.analyzers.diff.SymbolSnapshot;
import io.github.rezabakhshi.embedra.analyzers.diff.WorkspaceSnapshot;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Extracts a normalized, architecture-agnostic WorkspaceSnapshot from a Ghidra Program.
 */
public final class GhidraWorkspaceDiffExtractor {

    private static final Pattern SECRET_PATTERN = Pattern.compile(
            "(?i)(password|passwd|secret|api[_-]?key|bearer|token|private[_-]?key|credential|auth[_-]?token)"
    );

    public WorkspaceSnapshot extract(Program program) throws DiagnosticException {
        return extract(program, ParserLimits.defaults(), CancellationToken.none());
    }

    public WorkspaceSnapshot extract(Program program, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(program, "program cannot be null");
        ParserLimits effectiveLimits = limits != null ? limits : ParserLimits.defaults();
        CancellationToken effectiveToken = token != null ? token : CancellationToken.none();

        effectiveToken.throwIfCancellationRequested();

        List<FunctionSnapshot> functions = extractFunctions(program, effectiveLimits, effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<SymbolSnapshot> symbols = extractSymbols(program, effectiveLimits, effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<StringSnapshot> strings = extractStrings(program, effectiveLimits, effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<MetadataSnapshot> metadata = extractMetadata(program, effectiveLimits, effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<MemoryBlockSnapshot> memoryBlocks = extractMemoryBlocks(program, effectiveLimits, effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<PartitionSnapshot> partitions = extractPartitions(program, effectiveLimits, effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        return new WorkspaceSnapshot(
                program.getName(),
                functions,
                symbols,
                strings,
                metadata,
                memoryBlocks,
                partitions
        );
    }

    private List<FunctionSnapshot> extractFunctions(
            Program program, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        List<FunctionSnapshot> result = new ArrayList<>();
        FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
        int count = 0;
        while (iterator.hasNext() && count < limits.maxObjects()) {
            token.throwIfCancellationRequested();
            Function f = iterator.next();
            String name = f.getName();
            long addr = f.getEntryPoint().getOffset();
            long len = f.getBody().getNumAddresses();
            String hash = hashBytes(program, f.getEntryPoint(), len);
            String sig = f.getPrototypeString(true, false);
            result.add(new FunctionSnapshot(name, addr, len, hash, sig));
            count++;
        }
        return List.copyOf(result);
    }

    private List<SymbolSnapshot> extractSymbols(
            Program program, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        List<SymbolSnapshot> result = new ArrayList<>();
        SymbolIterator iterator = program.getSymbolTable().getAllSymbols(true);
        int count = 0;
        while (iterator.hasNext() && count < limits.maxObjects()) {
            token.throwIfCancellationRequested();
            Symbol s = iterator.next();
            if (s.isDynamic()) {
                continue; // Skip dynamic internal symbols for stable diffs
            }
            String name = s.getName();
            long addr = s.getAddress().getOffset();
            String type = s.getSymbolType().toString();
            String namespace = s.getParentNamespace() != null ? s.getParentNamespace().getName() : "";
            result.add(new SymbolSnapshot(name, addr, type, namespace));
            count++;
        }
        return List.copyOf(result);
    }

    private List<StringSnapshot> extractStrings(
            Program program, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        List<StringSnapshot> result = new ArrayList<>();
        DataIterator iterator = program.getListing().getDefinedData(true);
        int count = 0;
        while (iterator.hasNext() && count < limits.maxObjects()) {
            token.throwIfCancellationRequested();
            Data d = iterator.next();
            if (d.hasStringValue()) {
                Object val = d.getValue();
                if (val instanceof String strVal && !strVal.isBlank()) {
                    long addr = d.getAddress().getOffset();
                    DataType dt = d.getDataType();
                    String encoding = dt != null ? dt.getName() : "String";
                    boolean isSecret = isSecretString(strVal);
                    result.add(new StringSnapshot(strVal, addr, encoding, isSecret));
                    count++;
                }
            }
        }
        return List.copyOf(result);
    }

    private List<MetadataSnapshot> extractMetadata(
            Program program, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        List<MetadataSnapshot> result = new ArrayList<>();
        token.throwIfCancellationRequested();

        result.add(new MetadataSnapshot("Program Name", program.getName(), false));
        if (program.getLanguageID() != null) {
            result.add(new MetadataSnapshot("Language ID", program.getLanguageID().getIdAsString(), false));
        }
        if (program.getCompilerSpec() != null && program.getCompilerSpec().getCompilerSpecID() != null) {
            String cspecId = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
            result.add(new MetadataSnapshot("Compiler Spec", cspecId, false));
        }
        if (program.getExecutableFormat() != null) {
            result.add(new MetadataSnapshot("Executable Format", program.getExecutableFormat(), false));
        }
        if (program.getImageBase() != null) {
            String imgBase = String.format("0x%x", program.getImageBase().getOffset());
            result.add(new MetadataSnapshot("Image Base", imgBase, false));
        }
        if (program.getMemory() != null) {
            result.add(new MetadataSnapshot("Memory Size", String.valueOf(program.getMemory().getSize()), false));
        }

        // Program info options
        ghidra.framework.options.Options infoOpts = program.getOptions(Program.PROGRAM_INFO);
        if (infoOpts != null) {
            for (String optName : infoOpts.getOptionNames()) {
                token.throwIfCancellationRequested();
                Object obj = infoOpts.getObject(optName, null);
                String val = obj != null ? obj.toString() : "";
                boolean isSecret = SECRET_PATTERN.matcher(optName).find() || isSecretString(val);
                result.add(new MetadataSnapshot("Info." + optName, val, isSecret));
            }
        }

        return List.copyOf(result);
    }

    private List<MemoryBlockSnapshot> extractMemoryBlocks(
            Program program, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        List<MemoryBlockSnapshot> result = new ArrayList<>();
        if (program.getMemory() == null) {
            return List.of();
        }
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            token.throwIfCancellationRequested();
            String name = block.getName();
            long startAddr = block.getStart().getOffset();
            long size = block.getSize();
            String perms = (block.isRead() ? "R" : "-")
                    + (block.isWrite() ? "W" : "-")
                    + (block.isExecute() ? "X" : "-")
                    + (block.isVolatile() ? "V" : "-");
            String hash = hashBytes(program, block.getStart(), size);
            result.add(new MemoryBlockSnapshot(name, startAddr, size, perms, hash));
        }
        return List.copyOf(result);
    }

    private List<PartitionSnapshot> extractPartitions(
            Program program, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        List<PartitionSnapshot> result = new ArrayList<>();
        token.throwIfCancellationRequested();

        // 1. Search bookmarks with category containing partition
        BookmarkManager bm = program.getBookmarkManager();
        if (bm != null) {
            Iterator<Bookmark> iter = bm.getBookmarksIterator(BookmarkType.INFO);
            while (iter.hasNext()) {
                token.throwIfCancellationRequested();
                Bookmark b = iter.next();
                String cat = b.getCategory();
                if (cat != null && cat.toLowerCase(Locale.ROOT).contains("partition")) {
                    long offset = b.getAddress().getOffset();
                    String comment = b.getComment() != null ? b.getComment() : "";
                    result.add(new PartitionSnapshot(
                            comment.isBlank() ? ("part_" + Long.toHexString(offset)) : comment,
                            cat,
                            "app_or_data",
                            offset,
                            0x10000,
                            ""
                    ));
                }
            }
        }

        // 2. Check memory blocks for partition conventions (e.g. nvs, ota_0, factory, bootloader)
        if (result.isEmpty() && program.getMemory() != null) {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                token.throwIfCancellationRequested();
                String name = block.getName().toLowerCase(Locale.ROOT);
                if (name.contains("nvs") || name.contains("ota") || name.contains("factory")
                        || name.contains("phy_init") || name.contains("partition") || name.contains("storage")) {
                    result.add(new PartitionSnapshot(
                            block.getName(),
                            name.contains("ota") || name.contains("factory") ? "app" : "data",
                            name,
                            block.getStart().getOffset(),
                            block.getSize(),
                            ""
                    ));
                }
            }
        }

        return List.copyOf(result);
    }

    private static boolean isSecretString(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        if (SECRET_PATTERN.matcher(text).find()) {
            return true;
        }
        // PEM private keys
        if (text.contains("BEGIN PRIVATE KEY") || text.contains("BEGIN RSA PRIVATE KEY")) {
            return true;
        }
        // Base64/Hex high-entropy auth tokens / API keys (e.g. Bearer eyJ... or 32+ hex chars)
        if (text.startsWith("Bearer eyJ") || text.startsWith("ghp_") || text.startsWith("AKIA")) {
            return true;
        }
        return false;
    }

    private static String hashBytes(Program program, Address start, long length) {
        if (length <= 0 || program.getMemory() == null) {
            return "";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[1024];
            long remaining = Math.min(length, 65536L); // Bounded at 64KB
            Address current = start;
            while (remaining > 0) {
                int toRead = (int) Math.min(remaining, buffer.length);
                int read = program.getMemory().getBytes(current, buffer, 0, toRead);
                if (read <= 0) {
                    break;
                }
                md.update(buffer, 0, read);
                remaining -= read;
                current = current.add(read);
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
