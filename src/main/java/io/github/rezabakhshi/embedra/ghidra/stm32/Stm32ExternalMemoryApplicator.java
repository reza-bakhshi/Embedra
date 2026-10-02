package io.github.rezabakhshi.embedra.ghidra.stm32;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlan;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlanner
    .Stm32ExternalMemoryLoadPlan;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Transactional, non-destructive external-memory application for one exact part.
 *
 * <p>Every mapping originates from the confirmed external-memory plan: an
 * aperture block is created only for a pinned window with the pinned
 * writability, and loaded bytes go only to the planned device offset inside
 * that window. The application is bound to the program-recorded exact part and
 * fails closed on disagreement or on a program with no recorded part, runs
 * inside one rollback-capable transaction, is idempotent, preserves existing
 * user blocks, symbols, and bytes, and never resurrects a deleted or renamed
 * created block because receipt names are retained. Memory that already exists
 * is reported as a deterministic conflict and left untouched; neither
 * operation ever removes, splits, or overwrites an existing block.</p>
 */
public final class Stm32ExternalMemoryApplicator {
    /** Receipt namespace for T047 external-memory blocks and provenance. */
    public static final String EXTERNAL_MEMORY_OPTIONS = "Embedra STM32 External Memory";

    /** The window-mapping receipt operation. */
    public static final String OPERATION_MAP_WINDOWS = "MAP_WINDOWS";

    /** The byte-load receipt operation. */
    public static final String OPERATION_LOAD_BYTES = "LOAD_BYTES";

    private static final String BLOCK_PREFIX = "embedra_extmem_";

    private static final List<String> RECORDED_PART_OPTIONS = List.of(
        Stm32RawBinImporter.PROVENANCE_OPTIONS,
        "Embedra STM32 SVD",
        "Embedra STM32 Interrupts",
        Stm32VectorLabelApplicator.LABEL_OPTIONS,
        EXTERNAL_MEMORY_OPTIONS);

    private Stm32ExternalMemoryApplicator() {
    }

    /**
     * Maps every pinned external aperture as an uninitialized memory block.
     *
     * @param program the bound ARM program
     * @param plan the composed external-memory plan; must be mapped
     * @param monitor cooperative cancellation
     * @return the committed transaction receipt
     * @throws Stm32MappingException when the program is unbound, disagrees on
     *         the exact part, is not 32-bit little-endian ARM, or Ghidra
     *         rejects a block
     * @throws CancelledException when the caller cancels
     */
    public static Stm32ExternalMemoryReport mapWindows(Program program,
            Stm32ExternalMemoryPlan plan, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        if (!plan.mapped()) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "External memory is not mapped for " + plan.exactPart() + ": "
                    + plan.reason());
        }
        Context context = begin(program, plan.exactPart(), monitor);
        context.source = plan.source().name();
        context.board = plan.board();
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Map confirmed STM32 external-memory apertures")) {
            for (Stm32ExternalMemoryPlan.MappingWindow window : plan.windows()) {
                monitor.checkCancelled();
                mapWindow(context, window);
            }
            recordProvenance(context);
            transaction.commit();
        }
        return context.report(OPERATION_MAP_WINDOWS, 0);
    }

    /**
     * Loads caller-supplied bytes at the planned device offset of one pinned
     * external window.
     *
     * @param program the bound ARM program
     * @param provider the caller-supplied bytes; absent, truncated, or
     *        oversized inputs fail closed before any transaction opens
     * @param loadPlan the planned load placement
     * @param monitor cooperative cancellation
     * @return the committed transaction receipt
     * @throws Stm32MappingException when the input length disagrees with the
     *         plan, the program is unbound or disagrees on the exact part, the
     *         language is not 32-bit little-endian ARM, or Ghidra rejects a block
     * @throws CancelledException when the caller cancels
     */
    public static Stm32ExternalMemoryReport loadInto(Program program, ByteProvider provider,
            Stm32ExternalMemoryLoadPlan loadPlan, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException, IOException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(loadPlan, "loadPlan");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        if (provider.length() != loadPlan.length()) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "External-memory bytes do not match the planned load length: provider "
                    + provider.length() + ", planned " + loadPlan.length());
        }
        Context context = begin(program, loadPlan.exactPart(), monitor);
        context.source = loadPlan.source().name();
        context.device = loadPlan.deviceId();
        byte[] bytes;
        try {
            bytes = provider.readBytes(0, loadPlan.length());
        }
        catch (IOException exception) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "External-memory bytes could not be read", exception);
        }
        if (bytes.length != loadPlan.length()) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "External-memory provider returned " + bytes.length + " of the planned "
                    + loadPlan.length() + " bytes");
        }
        String name = loadBlockName(loadPlan.deviceId(), loadPlan.deviceOffset());
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Load bytes into confirmed STM32 external memory")) {
            Address start = address(context, loadPlan.cpuAddress());
            Address end = address(context, loadPlan.cpuAddress() + loadPlan.length() - 1);
            MemoryBlock named = context.program.getMemory().getBlock(name);
            if (named != null && named.getStart().equals(start)
                && named.getEnd().equals(end)) {
                confirmLoadedBlock(context, named, bytes);
            }
            else if (context.priorBlocks.contains(name) && named == null) {
                context.conflicts.add(new Stm32ExternalMemoryReport.Conflict(
                    loadPlan.cpuAddress(), "PRESERVED_ABSENT",
                    "User deleted the external-memory block " + name));
            }
            else if (!overlapsExisting(context, start, end)) {
                createBlock(context, name, start, loadPlan.length(), bytes,
                    loadPlan.writable());
                context.newReceipt.add(name);
                context.createdBlocks.add(new Stm32ExternalMemoryReport.Block(name,
                    loadPlan.cpuAddress(), loadPlan.length()));
                applyLabel(context, name, start);
            }
            recordProvenance(context);
            transaction.commit();
        }
        return context.report(OPERATION_LOAD_BYTES, bytes.length);
    }

    private static void mapWindow(Context context,
            Stm32ExternalMemoryPlan.MappingWindow window)
            throws Stm32MappingException, CancelledException {
        String name = windowBlockName(window.id());
        Address start = address(context, window.mappedRange().start());
        Address end = address(context, window.mappedRange().endExclusive() - 1);
        MemoryBlock named = context.program.getMemory().getBlock(name);
        if (named != null && named.getStart().equals(start) && named.getEnd().equals(end)
            && named.isRead() && named.isWrite() == window.writable() && !named.isExecute()
            && !named.isInitialized()) {
            return;
        }
        if (named != null) {
            context.conflicts.add(new Stm32ExternalMemoryReport.Conflict(
                window.mappedRange().start(), "MEMORY_PRESERVED",
                "Existing block " + named.getName() + " was not overwritten"));
            return;
        }
        if (context.priorBlocks.contains(name)) {
            context.conflicts.add(new Stm32ExternalMemoryReport.Conflict(
                window.mappedRange().start(), "PRESERVED_ABSENT",
                "User deleted the external-memory block " + name));
            return;
        }
        if (overlapsExisting(context, start, end)) {
            return;
        }
        createBlock(context, name, start, window.mappedRange().length(), null,
            window.writable());
        context.newReceipt.add(name);
        context.createdBlocks.add(new Stm32ExternalMemoryReport.Block(name,
            window.mappedRange().start(), window.mappedRange().length()));
        applyLabel(context, name, start);
    }

    /** Confirms our prior load block byte-for-byte or preserves its current content. */
    private static void confirmLoadedBlock(Context context, MemoryBlock named, byte[] bytes)
            throws Stm32MappingException {
        if (!named.isInitialized()) {
            context.conflicts.add(new Stm32ExternalMemoryReport.Conflict(
                named.getStart().getOffset(), "CONTENT_DIFFERS",
                "Existing block " + named.getName() + " is uninitialized and was kept"));
            return;
        }
        byte[] existing = new byte[bytes.length];
        try {
            context.program.getMemory().getBytes(named.getStart(), existing);
        }
        catch (ghidra.program.model.mem.MemoryAccessException exception) {
            throw new Stm32MappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "The prior external-memory block could not be read", exception);
        }
        if (Arrays.equals(existing, bytes)) {
            return;
        }
        context.conflicts.add(new Stm32ExternalMemoryReport.Conflict(
            named.getStart().getOffset(), "CONTENT_DIFFERS",
            "Existing block " + named.getName() + " holds different bytes and was kept"));
    }

    private static Context begin(Program program, String exactPart, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        monitor.checkCancelled();
        if (!program.getLanguageID().getIdAsString().startsWith("ARM:LE:32:")) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "External memory requires a selected 32-bit little-endian ARM program");
        }
        requireRecordedExactPart(program, exactPart);
        return new Context(program, exactPart, monitor);
    }

    /** Fails closed unless the program records exactly this part somewhere. */
    private static void requireRecordedExactPart(Program program, String exactPart)
            throws Stm32MappingException {
        Set<String> recorded = new LinkedHashSet<>();
        for (String namespace : RECORDED_PART_OPTIONS) {
            String value = program.getOptions(namespace).getString("Exact Part", null);
            if (value != null && !value.isBlank()) {
                recorded.add(value);
            }
        }
        if (recorded.isEmpty()) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "The program records no exact STM32 part; external memory cannot be "
                    + "mapped without a bound device");
        }
        if (recorded.size() > 1 || !recorded.contains(exactPart)) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "Program records a different exact STM32 part: "
                    + String.join(", ", recorded));
        }
    }

    /** Records a conflict and returns true when any existing block covers the range. */
    private static boolean overlapsExisting(Context context, Address start, Address end) {
        for (MemoryBlock existing : context.program.getMemory().getBlocks()) {
            if (start.compareTo(existing.getEnd()) <= 0
                && existing.getStart().compareTo(end) <= 0) {
                context.conflicts.add(new Stm32ExternalMemoryReport.Conflict(
                    start.getOffset(), "MEMORY_PRESERVED",
                    "Existing block " + existing.getName() + " was not overwritten"));
                return true;
            }
        }
        return false;
    }

    private static void createBlock(Context context, String name, Address start, long length,
            byte[] bytes, boolean writable) throws Stm32MappingException, CancelledException {
        try {
            MemoryBlock block;
            if (bytes == null) {
                block = context.program.getMemory().createUninitializedBlock(name, start,
                    length, false);
            }
            else {
                block = context.program.getMemory().createInitializedBlock(name, start,
                    new ByteArrayInputStream(bytes), bytes.length, context.monitor, false);
            }
            block.setRead(true);
            block.setWrite(writable);
            block.setExecute(false);
        }
        catch (Exception exception) {
            if (exception instanceof CancelledException cancelled) {
                throw cancelled;
            }
            throw new Stm32MappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected the external-memory block " + name, exception);
        }
    }

    private static void applyLabel(Context context, String name, Address target)
            throws Stm32MappingException {
        for (var symbol : context.program.getSymbolTable().getSymbols(target)) {
            if (symbol.getName().equals(name)) {
                return;
            }
        }
        if (context.program.getSymbolTable().getSymbols(name).hasNext()) {
            context.conflicts.add(new Stm32ExternalMemoryReport.Conflict(target.getOffset(),
                "NAME_CONFLICT", "External-memory label already exists elsewhere: " + name));
            return;
        }
        try {
            context.program.getSymbolTable().createLabel(target, name, SourceType.IMPORTED);
            context.createdSymbols.add(new Stm32ExternalMemoryReport.Symbol(name,
                target.getOffset()));
        }
        catch (InvalidInputException exception) {
            throw new Stm32MappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected an external-memory label", exception);
        }
    }

    private static void recordProvenance(Context context) {
        var options = context.program.getOptions(EXTERNAL_MEMORY_OPTIONS);
        options.setString("Exact Part", context.exactPart);
        options.setString("Source", context.source == null ? "" : context.source);
        options.setString("Board", context.board == null ? "" : context.board);
        options.setString("Device", context.device == null ? "" : context.device);
        Set<String> receipt = new LinkedHashSet<>();
        String prior = options.getString("Created Blocks", "");
        if (!prior.isBlank()) {
            receipt.addAll(Arrays.asList(prior.split(",")));
        }
        receipt.addAll(context.newReceipt);
        options.setString("Created Blocks", String.join(",", receipt));
    }

    private static String windowBlockName(String windowId) {
        return BLOCK_PREFIX + safe(windowId).toLowerCase(Locale.ROOT);
    }

    private static String loadBlockName(String deviceId, long deviceOffset) {
        return BLOCK_PREFIX + safe(deviceId).toLowerCase(Locale.ROOT) + "_load_"
            + Long.toHexString(deviceOffset);
    }

    private static String safe(String value) {
        return value.replaceAll("[^A-Za-z0-9_$]", "_");
    }

    private static Address address(Context context, long offset) throws Stm32MappingException {
        try {
            return context.program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(offset);
        }
        catch (RuntimeException exception) {
            throw new Stm32MappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "External-memory address is outside the program address space", exception);
        }
    }

    private static final class Context {
        private final Program program;

        private final String exactPart;

        private final TaskMonitor monitor;

        private final Set<String> priorBlocks = new LinkedHashSet<>();

        private final Set<String> newReceipt = new LinkedHashSet<>();

        private final List<Stm32ExternalMemoryReport.Block> createdBlocks = new ArrayList<>();

        private final List<Stm32ExternalMemoryReport.Symbol> createdSymbols = new ArrayList<>();

        private final List<Stm32ExternalMemoryReport.Conflict> conflicts = new ArrayList<>();

        private String source;

        private String board;

        private String device;

        private Context(Program program, String exactPart, TaskMonitor monitor) {
            this.program = program;
            this.exactPart = exactPart;
            this.monitor = monitor;
            String receipt = program.getOptions(EXTERNAL_MEMORY_OPTIONS)
                .getString("Created Blocks", "");
            if (!receipt.isBlank()) {
                priorBlocks.addAll(Arrays.asList(receipt.split(",")));
            }
        }

        private Stm32ExternalMemoryReport report(String operation, long loadedByteCount) {
            return new Stm32ExternalMemoryReport(true, exactPart, operation, source,
                createdBlocks, createdSymbols, conflicts, loadedByteCount);
        }
    }
}
