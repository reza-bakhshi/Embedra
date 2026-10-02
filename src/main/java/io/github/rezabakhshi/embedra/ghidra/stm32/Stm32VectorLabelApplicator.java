package io.github.rezabakhshi.embedra.ghidra.stm32;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32VectorDiscovery;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32InterruptPlan;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.vector.Stm32VectorPlan;
import io.github.rezabakhshi.embedra.targets.stm32.vector.Stm32VectorPlanner;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Transactionally applies confirmed STM32 vector labels, handler functions, and
 * core-exception structures.
 *
 * <p>The adapter never plans names or addresses itself. It verifies the confirmed
 * table words against the T037 candidate, reads the bounded confirmed words for
 * every exact-part interrupt slot, and delegates naming/address resolution to the
 * pure planner. User symbols, functions, data, instructions, and comments are
 * preserved; prior receipt addresses are never resurrected; and any mutation
 * rolls back unless the whole operation commits.</p>
 */
public final class Stm32VectorLabelApplicator {
    /** Reuses the T037 confirmation record so one program has one confirmed table. */
    public static final String CONFIRMATION_OPTIONS = Stm32VectorApplicator.PROVENANCE_OPTIONS;

    /** Receipt namespace for T041 labels, functions, and counts. */
    public static final String LABEL_OPTIONS = "Embedra STM32 Vector Labels";

    /** The only supported confirmation method; a table is never inferred. */
    public static final String CONFIRMATION_METHOD = "USER_CONFIRMED";

    private static final List<String> RECORDED_PART_OPTIONS = List.of(
        Stm32RawBinImporter.PROVENANCE_OPTIONS,
        "Embedra STM32 SVD",
        "Embedra STM32 Interrupts",
        LABEL_OPTIONS);

    private Stm32VectorLabelApplicator() {
    }

    /**
     * Applies confirmed vector labels and functions for one exact part.
     *
     * @param program program with the confirmed vector bytes already mapped
     * @param confirmed explicit T037 confirmation of a discovered table
     * @param interrupts exact-part interrupt list; must be a single applicable header
     * @param imageBase confirmed image base used to validate handler containment
     * @param imageLength confirmed image length in bytes
     * @param monitor cooperative cancellation
     * @return the committed transaction receipt
     * @throws Stm32MappingException when the table, interrupt list, or range is unsafe
     * @throws CancelledException when the caller cancels
     */
    public static Stm32VectorApplicationReport apply(Program program,
            Stm32VectorDiscovery.Confirmed confirmed, Stm32InterruptPlan.Entry interrupts,
            long imageBase, long imageLength, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(confirmed, "confirmed");
        Objects.requireNonNull(interrupts, "interrupts");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        if (!program.getLanguageID().getIdAsString().startsWith("ARM:LE:32:")) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "Vector labels require a selected little-endian ARM program");
        }
        requireRecordedPartMatches(program, interrupts.exactPart());
        var candidate = confirmed.candidate();
        verifyConfirmedTable(program, candidate, monitor);
        List<Long> words = readWords(program, candidate.tableAddress(),
            requiredSlots(interrupts), monitor);
        Stm32VectorPlan plan = Stm32VectorPlanner.plan(interrupts, words,
            candidate.tableAddress(), imageBase, imageLength);
        if (!plan.applicable()) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "Vector labels are not applicable: " + plan.reason());
        }
        Context context = new Context(program, plan, candidate);
        context.loadReceipt();
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply confirmed STM32 vector labels and functions")) {
            confirmVectorData(context);
            for (Stm32VectorPlan.Slot slot : plan.slots()) {
                monitor.checkCancelled();
                applySlot(context, slot);
            }
            recordProvenance(context);
            transaction.commit();
        }
        catch (EnrichmentFailure failure) {
            throw failure.exception;
        }
        return context.report();
    }

    /**
     * Applies confirmed vector labels using the exact-part T039 memory plan for
     * the image extent, so the caller does not hard-code a flash base or length.
     */
    public static Stm32VectorApplicationReport apply(Program program,
            Stm32VectorDiscovery.Confirmed confirmed, Stm32InterruptPlan.Entry interrupts,
            Stm32MemoryPlanner.Plan memoryPlan, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        Objects.requireNonNull(memoryPlan, "memoryPlan");
        Objects.requireNonNull(interrupts, "interrupts");
        if (!memoryPlan.exactPart().equals(interrupts.exactPart())) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "Memory plan does not match the exact interrupt part");
        }
        Stm32VectorPlanner.ImageRange range;
        try {
            range = Stm32VectorPlanner.flashImageRange(memoryPlan);
        }
        catch (IllegalArgumentException exception) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "T039 memory plan has no confirmed flash image range", exception);
        }
        return apply(program, confirmed, interrupts, range.base(), range.length(), monitor);
    }

    private static void requireRecordedPartMatches(Program program, String exactPart)
            throws Stm32MappingException {
        for (String namespace : RECORDED_PART_OPTIONS) {
            String recorded = program.getOptions(namespace).getString("Exact Part", null);
            if (recorded != null && !recorded.isBlank() && !recorded.equals(exactPart)) {
                throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                    "Program records a different exact STM32 part: " + recorded);
            }
        }
    }

    private static void verifyConfirmedTable(Program program,
            Stm32VectorDiscovery.Candidate candidate, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        Address base = address(program, candidate.tableAddress());
        var options = program.getOptions(CONFIRMATION_OPTIONS);
        long existing = options.getLong("Confirmed Vector Address", -1);
        if (existing != -1 && existing != candidate.tableAddress()) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "Program already records another confirmed vector table");
        }
        for (int index = 0; index < candidate.words().size(); index++) {
            monitor.checkCancelled();
            Address vector;
            try {
                vector = base.addNoWrap(index * 4L);
            }
            catch (AddressOverflowException exception) {
                throw new Stm32MappingException(DiagnosticCode.PACK_CONTENT_INVALID,
                    "Confirmed vector table exceeds the 32-bit address space", exception);
            }
            long mapped = readInt(program, vector,
                "Mapped vector bytes are unavailable");
            if (mapped != candidate.words().get(index)) {
                throw new Stm32MappingException(DiagnosticCode.PACK_CONTENT_INVALID,
                    "Mapped vector bytes differ from the confirmed candidate");
            }
            if (program.getListing().getInstructionContaining(vector) != null) {
                throw new Stm32MappingException(DiagnosticCode.PACK_CONTENT_INVALID,
                    "Existing instruction conflicts with confirmed vector");
            }
            Data data = program.getListing().getDefinedDataContaining(vector);
            if (data != null && (data.getMinAddress().compareTo(vector) != 0
                    || !data.getDataType().isEquivalent(DWordDataType.dataType))) {
                throw new Stm32MappingException(DiagnosticCode.PACK_CONTENT_INVALID,
                    "Existing data conflicts with confirmed vector");
            }
        }
    }

    private static List<Long> readWords(Program program, long tableAddress, int maxSlot,
            TaskMonitor monitor) throws Stm32MappingException, CancelledException {
        List<Long> words = new ArrayList<>(maxSlot + 1);
        for (int slot = 0; slot <= maxSlot; slot++) {
            monitor.checkCancelled();
            Address vector;
            try {
                vector = address(program, add(tableAddress, slot * 4L));
            }
            catch (IllegalArgumentException exception) {
                throw new Stm32MappingException(DiagnosticCode.PACK_CONTENT_INVALID,
                    "Confirmed vector table exceeds the 32-bit address space", exception);
            }
            words.add(readInt(program, vector, "Confirmed vector table is truncated at slot " + slot));
        }
        return words;
    }

    private static void confirmVectorData(Context context) throws EnrichmentFailure {
        Address base = address(context.program, context.candidate.tableAddress());
        try {
            for (int index = 0; index < Stm32VectorPlanner.CORE_SLOTS; index++) {
                Address vector;
                try {
                    vector = base.addNoWrap(index * 4L);
                }
                catch (AddressOverflowException exception) {
                    throw new EnrichmentFailure(new Stm32MappingException(
                        DiagnosticCode.PACK_CONTENT_INVALID,
                        "Confirmed vector table exceeds the 32-bit address space", exception));
                }
                if (context.program.getListing().getDefinedDataAt(vector) == null) {
                    context.program.getListing().createData(vector, DWordDataType.dataType);
                }
            }
            var options = context.program.getOptions(CONFIRMATION_OPTIONS);
            if (options.getLong("Confirmed Vector Address", -1) == -1) {
                options.setLong("Confirmed Vector Address", context.candidate.tableAddress());
                options.setString("Selection", CONFIRMATION_METHOD);
                options.setString("Input SHA-256", context.candidate.inputSha256());
            }
        }
        catch (CodeUnitInsertionException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected confirmed vector data", exception));
        }
    }

    private static void applySlot(Context context, Stm32VectorPlan.Slot slot)
            throws EnrichmentFailure {
        if (slot.name() == null) {
            return;
        }
        if (!slot.resolvedHandler()) {
            context.conflicts.add(new Stm32VectorApplicationReport.Conflict(
                slotAddress(context, slot.slot()), "UNRESOLVED_HANDLER",
                slot.label() + " handler status " + slot.handlerStatus()));
            return;
        }
        long handler = slot.handlerAddress();
        String first = context.handledHandlers.get(handler);
        if (first != null) {
            context.aliasedSlots++;
            context.conflicts.add(new Stm32VectorApplicationReport.Conflict(handler, "ALIASED",
                slot.label() + " shares a handler with " + first));
            return;
        }
        context.handledHandlers.put(handler, slot.label());
        Address target = address(context.program, handler);
        if (context.program.getMemory().getBlock(target) == null) {
            context.conflicts.add(new Stm32VectorApplicationReport.Conflict(handler,
                "UNMAPPED_HANDLER", "Handler address is not mapped: " + slot.label()));
            return;
        }
        if (!applyHandlerFunction(context, slot, target, handler)) {
            return;
        }
        applyHandlerLabel(context, slot, target, handler);
    }

    /** Returns false when the user's existing artifact must be preserved unchanged. */
    private static boolean applyHandlerFunction(Context context, Stm32VectorPlan.Slot slot,
            Address target, long handler) throws EnrichmentFailure {
        boolean ours = context.priorFunctions.contains(handler);
        Function existing = context.program.getFunctionManager().getFunctionAt(target);
        if (existing != null) {
            if (!ours) {
                context.conflicts.add(new Stm32VectorApplicationReport.Conflict(handler,
                    "FUNCTION_PRESERVED",
                    "Existing function " + existing.getName() + " was not overwritten"));
                return false;
            }
            if (namedSymbol(context.program, slot.label(), target) == null) {
                context.conflicts.add(new Stm32VectorApplicationReport.Conflict(handler,
                    "PRESERVED_ABSENT", "User removed or renamed " + slot.label()));
                return false;
            }
            return true;
        }
        if (ours) {
            context.conflicts.add(new Stm32VectorApplicationReport.Conflict(handler,
                "PRESERVED_ABSENT", "User deleted " + slot.label()));
            return false;
        }
        if (context.program.getListing().getDefinedDataAt(target) != null) {
            context.conflicts.add(new Stm32VectorApplicationReport.Conflict(handler,
                "DATA_PRESERVED", "Existing data at handler entry was not overwritten: "
                    + slot.label()));
            return true;
        }
        try {
            context.program.getFunctionManager().createFunction(slot.label(), target,
                new AddressSet(target, target), SourceType.IMPORTED);
        }
        catch (InvalidInputException | OverlappingFunctionException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected a vector handler function", exception));
        }
        context.createdFunctions++;
        context.createdFunctionAddresses.add(handler);
        context.createdSymbols.add(new Stm32VectorApplicationReport.Symbol(
            slot.label(), handler, true));
        context.newFunctions.add(handler);
        return true;
    }

    private static void applyHandlerLabel(Context context, Stm32VectorPlan.Slot slot,
            Address target, long handler) throws EnrichmentFailure {
        if (namedSymbol(context.program, slot.label(), target) != null) {
            return;
        }
        if (nameExistsElsewhere(context.program, slot.label(), target)) {
            context.conflicts.add(new Stm32VectorApplicationReport.Conflict(handler,
                "NAME_CONFLICT", "Vector label already exists elsewhere: " + slot.label()));
            return;
        }
        if (context.priorLabels.contains(token(slot.label(), handler))) {
            context.conflicts.add(new Stm32VectorApplicationReport.Conflict(handler,
                "PRESERVED_ABSENT", "User deleted " + slot.label()));
            return;
        }
        try {
            Symbol primary = context.program.getSymbolTable().getPrimarySymbol(target);
            Symbol imported = context.program.getSymbolTable().createLabel(target, slot.label(),
                SourceType.IMPORTED);
            if (primary != null && imported.isPrimary()) {
                primary.setPrimary();
            }
        }
        catch (InvalidInputException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected a vector label", exception));
        }
        context.createdLabels++;
        context.createdSymbols.add(new Stm32VectorApplicationReport.Symbol(
            slot.label(), handler, false));
        context.newLabels.add(token(slot.label(), handler));
    }

    private static void recordProvenance(Context context) {
        var options = context.program.getOptions(LABEL_OPTIONS);
        options.setString("Exact Part", context.plan.exactPart());
        options.setLong("Vector Table Address", context.plan.tableAddress().orElse(-1));
        options.setString("Source SHA-256", context.candidate.inputSha256());
        options.setString("Confirmation Method", CONFIRMATION_METHOD);
        options.setInt("Vector Slot Count", context.plan.slots().size());
        options.setInt("Named Slot Count", context.plan.namedSlots().size());
        options.setInt("Resolved Handler Count", context.resolvedHandlers());
        options.setInt("Created Label Count", context.createdLabels);
        options.setInt("Created Function Count", context.createdFunctions);
        options.setInt("Aliased Slot Count", context.aliasedSlots);
        options.setString("Created Function Addresses",
            joinHex(merge(context.priorFunctions, context.newFunctions)));
        options.setString("Created Label Tokens",
            joinTokens(merge(context.priorLabels, context.newLabels)));
    }

    private static String joinHex(Set<Long> values) {
        List<Long> sorted = new ArrayList<>(values);
        sorted.sort(null);
        StringBuilder builder = new StringBuilder();
        for (long value : sorted) {
            if (builder.length() > 0) {
                builder.append(',');
            }
            builder.append(String.format(Locale.ROOT, "%08x", value));
        }
        return builder.toString();
    }

    private static Set<Long> parseHex(String value) {
        Set<Long> parsed = new LinkedHashSet<>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                parsed.add(Long.parseUnsignedLong(trimmed, 16));
            }
        }
        return parsed;
    }

    private static String joinTokens(Set<String> values) {
        List<String> sorted = new ArrayList<>(values);
        sorted.sort(null);
        return String.join(",", sorted);
    }

    private static Set<String> parseTokens(String value) {
        Set<String> parsed = new LinkedHashSet<>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                parsed.add(trimmed);
            }
        }
        return parsed;
    }

    private static <T> Set<T> merge(Set<T> left, Set<T> right) {
        Set<T> merged = new LinkedHashSet<>(left);
        merged.addAll(right);
        return merged;
    }

    private static String token(String label, long address) {
        return label + "@" + String.format(Locale.ROOT, "%08x", address);
    }

    private static Symbol namedSymbol(Program program, String name, Address target) {
        for (Symbol symbol : program.getSymbolTable().getSymbols(target)) {
            if (symbol.getName().equals(name)) {
                return symbol;
            }
        }
        return null;
    }

    private static boolean nameExistsElsewhere(Program program, String name, Address target) {
        for (Symbol symbol : program.getSymbolTable().getSymbols(name)) {
            if (!symbol.getAddress().equals(target)) {
                return true;
            }
        }
        return false;
    }

    private static long readInt(Program program, Address address, String message)
            throws Stm32MappingException {
        try {
            return Integer.toUnsignedLong(program.getMemory().getInt(address));
        }
        catch (MemoryAccessException | RuntimeException exception) {
            throw new Stm32MappingException(DiagnosticCode.PACK_CONTENT_INVALID, message,
                exception);
        }
    }

    private static int requiredSlots(Stm32InterruptPlan.Entry entry) {
        int max = Stm32VectorPlanner.CORE_SLOTS - 1;
        for (Stm32InterruptPlan.Interrupt interrupt : entry.interrupts()) {
            if (interrupt.number() >= 0) {
                max = Math.max(max, Stm32VectorPlanner.CORE_SLOTS + interrupt.number());
            }
        }
        return max;
    }

    private static long slotAddress(Context context, int slot) {
        return add(context.candidate.tableAddress(), slot * 4L);
    }

    private static long add(long base, long offset) {
        long value = base + offset;
        if (value < 0 || value >= 0x1_0000_0000L) {
            throw new IllegalArgumentException("Vector address exceeds the 32-bit space");
        }
        return value;
    }

    private static Address address(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static final class EnrichmentFailure extends Exception {
        private static final long serialVersionUID = 1L;

        private final Stm32MappingException exception;

        private EnrichmentFailure(Stm32MappingException exception) {
            super(exception);
            this.exception = exception;
        }
    }

    private static final class Context {
        private final Program program;

        private final Stm32VectorPlan plan;

        private final Stm32VectorDiscovery.Candidate candidate;

        private final Map<Long, String> handledHandlers = new LinkedHashMap<>();

        private final Set<Long> priorFunctions = new LinkedHashSet<>();

        private final Set<String> priorLabels = new LinkedHashSet<>();

        private final Set<Long> newFunctions = new LinkedHashSet<>();

        private final Set<String> newLabels = new LinkedHashSet<>();

        private final List<Stm32VectorApplicationReport.Symbol> createdSymbols = new ArrayList<>();

        private final List<Long> createdFunctionAddresses = new ArrayList<>();

        private final List<Stm32VectorApplicationReport.Conflict> conflicts = new ArrayList<>();

        private int createdLabels;

        private int createdFunctions;

        private int aliasedSlots;

        private Context(Program program, Stm32VectorPlan plan,
                Stm32VectorDiscovery.Candidate candidate) {
            this.program = program;
            this.plan = plan;
            this.candidate = candidate;
        }

        private void loadReceipt() {
            var options = program.getOptions(LABEL_OPTIONS);
            priorFunctions.addAll(parseHex(options.getString("Created Function Addresses", "")));
            priorLabels.addAll(parseTokens(options.getString("Created Label Tokens", "")));
        }

        private int resolvedHandlers() {
            return Math.toIntExact(plan.namedSlots().stream()
                .filter(Stm32VectorPlan.Slot::resolvedHandler).count());
        }

        private Stm32VectorApplicationReport report() {
            return new Stm32VectorApplicationReport(true, plan.exactPart(),
                plan.tableAddress().orElse(-1), candidate.inputSha256(), CONFIRMATION_METHOD,
                plan.slots().size(), plan.namedSlots().size(), resolvedHandlers(),
                createdLabels, createdFunctions, aliasedSlots, createdSymbols,
                createdFunctionAddresses, conflicts,
                plan.diagnostics().stream().map(diagnostic ->
                    new Stm32VectorApplicationReport.Diagnostic(diagnostic.code(),
                        diagnostic.detail())).toList());
        }
    }
}
