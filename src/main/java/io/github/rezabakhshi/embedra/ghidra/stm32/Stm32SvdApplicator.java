package io.github.rezabakhshi.embedra.ghidra.stm32;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.pack.Stm32SvdPack;
import io.github.rezabakhshi.embedra.svd.Stm32SvdEnumeratedValue;
import io.github.rezabakhshi.embedra.svd.Stm32SvdField;
import io.github.rezabakhshi.embedra.svd.Stm32SvdInterrupt;
import io.github.rezabakhshi.embedra.svd.Stm32SvdPeripheral;
import io.github.rezabakhshi.embedra.svd.Stm32SvdRegister;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32InterruptPlan;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** Transactional, non-destructive application of verified STM32 device data. */
public final class Stm32SvdApplicator {
    private static final List<String> RECORDED_PART_OPTIONS = List.of(
        Stm32RawBinImporter.PROVENANCE_OPTIONS,
        "Embedra STM32 SVD",
        "Embedra STM32 Interrupts",
        Stm32VectorLabelApplicator.LABEL_OPTIONS);

    private Stm32SvdApplicator() {
    }

    public static Stm32DeviceDataReport applyRegisters(Program program, Stm32SvdPack pack,
            String exactPart, Stm32PartSelection selection, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        Objects.requireNonNull(pack, "pack");
        Context context = begin(program, exactPart, selection, monitor);
        context.pack = pack;
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply verified STM32 SVD registers")) {
            applyPack(context, pack);
            transaction.commit();
        }
        catch (EnrichmentFailure failure) {
            throw failure.exception;
        }
        return context.report();
    }

    public static Stm32DeviceDataReport applyInterrupts(Program program,
            Stm32InterruptPlan.Entry interrupts, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        Objects.requireNonNull(interrupts, "interrupts");
        Context context = begin(program, interrupts.exactPart(), null, monitor);
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply verified STM32 interrupt definitions")) {
            applyInterrupts(context, interrupts);
            transaction.commit();
        }
        catch (EnrichmentFailure failure) {
            throw failure.exception;
        }
        return context.report();
    }

    public static Stm32DeviceDataReport applyAll(Program program, Stm32SvdPack pack,
            String exactPart, Stm32InterruptPlan.Entry interrupts,
            Stm32PartSelection selection, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        Objects.requireNonNull(pack, "pack");
        Objects.requireNonNull(interrupts, "interrupts");
        if (!Objects.equals(exactPart, interrupts.exactPart())) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "Interrupt definitions do not match the selected exact STM32 part");
        }
        Context context = begin(program, exactPart, selection, monitor);
        context.pack = pack;
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply verified STM32 device data")) {
            applyPack(context, pack);
            applyInterrupts(context, interrupts);
            transaction.commit();
        }
        catch (EnrichmentFailure failure) {
            throw failure.exception;
        }
        return context.report();
    }

    private static Context begin(Program program, String exactPart,
            Stm32PartSelection selection, TaskMonitor monitor)
            throws Stm32MappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        if (selection != null && !selection.containsExactPart(exactPart)) {
            throw new Stm32MappingException(DiagnosticCode.PACK_INCOMPATIBLE,
                "Device data does not name an exact curated STM32 part");
        }
        requireRecordedPartMatches(program, exactPart);
        return new Context(program, exactPart, monitor);
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

    private static void applyPack(Context context, Stm32SvdPack pack)
            throws EnrichmentFailure, CancelledException {
        if (!pack.manifest().supportedDevices().contains(context.exactPart)) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_INCOMPATIBLE,
                "SVD pack does not list the selected exact part"));
        }
        context.pack = pack;
        context.core = pack.cpu();
        for (Stm32SvdPeripheral peripheral : context.device().peripherals()) {
            context.monitor.checkCancelled();
            ensureBlock(context, peripheral);
            applyLabel(context, peripheral.name(), peripheral.baseAddress());
            context.comments += comment(context, peripheral.baseAddress(),
                peripheral.description());
            for (Stm32SvdRegister register : peripheral.registers()) {
                context.monitor.checkCancelled();
                String label = label(peripheral.name(), register.name());
                applyLabel(context, label, register.address());
                applyType(context, peripheral, register);
                context.comments += comment(context, register.address(),
                    register.description());
            }
        }
        recordRegisterIdentity(context, pack);
    }

    private static void applyInterrupts(Context context,
            Stm32InterruptPlan.Entry interrupts) throws EnrichmentFailure, CancelledException {
        context.interrupts = interrupts;
        if (!interrupts.applicable()) {
            recordInterruptIdentity(context, interrupts, 0);
            return;
        }
        String name = safe(context.exactPart) + "_IRQn";
        CategoryPath category = new CategoryPath(
            "/Embedra/" + safe(context.exactPart) + "/Interrupts");
        EnumDataType enumeration = new EnumDataType(category, name, 4,
            context.program.getDataTypeManager());
        for (Stm32InterruptPlan.Interrupt interrupt : interrupts.interrupts()) {
            enumeration.add(safe(interrupt.name()), interrupt.number(), null);
        }
        try {
            context.program.getDataTypeManager().resolve(enumeration,
                DataTypeConflictHandler.KEEP_HANDLER);
        }
        catch (IllegalArgumentException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected STM32 interrupt definitions", exception));
        }
        context.interruptCount = interrupts.interrupts().size();
        recordInterruptIdentity(context, interrupts, context.interruptCount);
    }

    private static void ensureBlock(Context context, Stm32SvdPeripheral peripheral)
            throws EnrichmentFailure {
        String name = "embedra_svd_" + safe(peripheral.name()).toLowerCase(Locale.ROOT);
        Address start = address(context, peripheral.baseAddress());
        Address end = address(context, peripheral.endExclusive() - 1);
        MemoryBlock named = context.program.getMemory().getBlock(name);
        if (named != null && named.getStart().equals(start) && named.getEnd().equals(end)
            && named.isRead() && named.isWrite() && named.isVolatile()) {
            return;
        }
        for (MemoryBlock existing : context.program.getMemory().getBlocks()) {
            if (start.compareTo(existing.getEnd()) <= 0
                && existing.getStart().compareTo(end) <= 0) {
                context.conflicts.add(new Stm32DeviceDataReport.Conflict(
                    peripheral.baseAddress(), "MEMORY_PRESERVED",
                    "Existing block " + existing.getName() + " was not overwritten by SVD data"));
                return;
            }
        }
        try {
            long length = peripheral.endExclusive() - peripheral.baseAddress();
            MemoryBlock block = context.program.getMemory().createUninitializedBlock(
                name, start, length, false);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(false);
            block.setVolatile(true);
            context.blocks.add(new Stm32DeviceDataReport.Block(name,
                peripheral.baseAddress(), length));
        }
        catch (LockException | MemoryConflictException | AddressOverflowException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected an SVD peripheral block", exception));
        }
    }

    private static void applyLabel(Context context, String name, long offset)
            throws EnrichmentFailure {
        Address target = address(context, offset);
        if (context.program.getMemory().getBlock(target) == null) {
            context.conflicts.add(new Stm32DeviceDataReport.Conflict(offset,
                "UNMAPPED_SYMBOL", "SVD symbol address is not mapped: " + name));
            return;
        }
        for (Symbol symbol : context.program.getSymbolTable().getSymbols(target)) {
            if (symbol.getName().equals(name)) {
                return;
            }
        }
        if (context.program.getSymbolTable().getSymbols(name).hasNext()) {
            context.conflicts.add(new Stm32DeviceDataReport.Conflict(offset,
                "NAME_CONFLICT", "SVD symbol name already exists elsewhere: " + name));
            return;
        }
        try {
            Symbol primary = context.program.getSymbolTable().getPrimarySymbol(target);
            Symbol imported = context.program.getSymbolTable().createLabel(target, name,
                SourceType.IMPORTED);
            if (primary != null && imported.isPrimary()) {
                primary.setPrimary();
            }
            context.symbols.add(new Stm32DeviceDataReport.Symbol(name, offset));
        }
        catch (InvalidInputException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected an SVD symbol", exception));
        }
    }

    private static void applyType(Context context, Stm32SvdPeripheral peripheral,
            Stm32SvdRegister register) throws EnrichmentFailure {
        Address target = address(context, register.address());
        if (context.program.getMemory().getBlock(target) == null) {
            return;
        }
        DataType proposed;
        try {
            proposed = registerType(context, peripheral, register);
        }
        catch (InvalidDataTypeException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected an SVD register type", exception));
        }
        Data existing = context.program.getListing().getDefinedDataContaining(target);
        if (existing != null) {
            if (!existing.getDataType().isEquivalent(proposed)) {
                context.conflicts.add(new Stm32DeviceDataReport.Conflict(register.address(),
                    register.isAlternateView() ? "ALTERNATE_VIEW_PRESERVED" : "TYPE_PRESERVED",
                    "Existing data type was not overwritten by SVD data"));
            }
            return;
        }
        if (context.program.getListing().getInstructionContaining(target) != null) {
            context.conflicts.add(new Stm32DeviceDataReport.Conflict(register.address(),
                "INSTRUCTION_PRESERVED", "Existing instruction was not overwritten"));
            return;
        }
        try {
            context.program.getListing().createData(target, proposed);
            context.dataAddresses.add(register.address());
        }
        catch (CodeUnitInsertionException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected SVD register data", exception));
        }
    }

    private static DataType registerType(Context context, Stm32SvdPeripheral peripheral,
            Stm32SvdRegister register) throws InvalidDataTypeException {
        if (!register.hasFields()) {
            return switch (register.sizeBits()) {
                case 8 -> ByteDataType.dataType;
                case 16 -> WordDataType.dataType;
                case 64 -> QWordDataType.dataType;
                default -> DWordDataType.dataType;
            };
        }
        int sizeBytes = register.sizeBits() / 8;
        String typeName = label(peripheral.name(), register.name()) + "_t";
        StructureDataType structure = new StructureDataType(context.category(), typeName,
            sizeBytes, context.program.getDataTypeManager());
        for (Stm32SvdField field : register.fields()) {
            DataType fieldType = field.enumeratedValues().isEmpty()
                ? UnsignedIntegerDataType.dataType : enumType(context, typeName, field);
            structure.insertBitFieldAt(0, sizeBytes, field.bitOffset(), fieldType,
                field.bitWidth(), safe(field.name()),
                commentText(field));
        }
        return context.program.getDataTypeManager().resolve(structure,
            DataTypeConflictHandler.KEEP_HANDLER);
    }

    private static DataType enumType(Context context, String registerType,
            Stm32SvdField field) {
        int sizeBytes = sizeBytesFor(field.bitWidth());
        EnumDataType enumeration = new EnumDataType(context.category(),
            registerType + "_" + safe(field.name()) + "_e", sizeBytes,
            context.program.getDataTypeManager());
        for (Stm32SvdEnumeratedValue value : field.enumeratedValues()) {
            enumeration.add(safe(value.name()), value.value(),
                value.description().isBlank() ? null : value.description());
        }
        context.enumerations++;
        return context.program.getDataTypeManager().resolve(enumeration,
            DataTypeConflictHandler.KEEP_HANDLER);
    }

    private static int sizeBytesFor(int bitWidth) {
        if (bitWidth <= 8) {
            return 1;
        }
        if (bitWidth <= 16) {
            return 2;
        }
        if (bitWidth <= 32) {
            return 4;
        }
        return 8;
    }

    private static String commentText(Stm32SvdField field) {
        List<String> parts = new ArrayList<>();
        if (!field.description().isBlank()) {
            parts.add(field.description());
        }
        field.readAction().ifPresent(action -> parts.add("read action: " + action));
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    private static int comment(Context context, long offset, String description)
            throws EnrichmentFailure {
        if (description.isBlank()) {
            return 0;
        }
        Address target = address(context, offset);
        if (context.program.getMemory().getBlock(target) == null
            || context.program.getListing().getComment(CommentType.EOL, target) != null) {
            return 0;
        }
        context.program.getListing().setComment(target, CommentType.EOL,
            "Embedra STM32 SVD: " + description);
        return 1;
    }

    private static void recordRegisterIdentity(Context context, Stm32SvdPack pack) {
        var options = context.program.getOptions("Embedra STM32 SVD");
        options.setString("Pack ID", pack.manifest().packId());
        options.setString("Pack Version", pack.manifest().version().toString());
        options.setString("Pack Digest", pack.manifest().contentDigest());
        options.setString("Source Revision", pack.device().sourceRevision());
        options.setString("Source File", pack.sourceFile());
        options.setString("Source File SHA-256", pack.sourceFileSha256());
        options.setString("Exact Part", context.exactPart);
        options.setString("Core", context.core == null ? "" : context.core);
        options.setInt("Register Count", Math.toIntExact(pack.registerCount()));
        options.setInt("Field Count", Math.toIntExact(pack.fieldCount()));
    }

    private static void recordInterruptIdentity(Context context,
            Stm32InterruptPlan.Entry interrupts, int count) {
        var options = context.program.getOptions("Embedra STM32 Interrupts");
        options.setString("Exact Part", interrupts.exactPart());
        options.setString("Interrupt Status", interrupts.status());
        options.setString("Interrupt Header",
            interrupts.header() == null ? "" : interrupts.header());
        options.setInt("Interrupt Count", count);
    }

    private static String label(String peripheral, String register) {
        String qualified = register.startsWith(peripheral + "_")
            ? register : peripheral + "_" + register;
        return safe(qualified + "_REG");
    }

    private static String safe(String value) {
        return value.replaceAll("[^A-Za-z0-9_$]", "_");
    }

    private static Address address(Context context, long offset) throws EnrichmentFailure {
        try {
            return context.program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        catch (RuntimeException exception) {
            throw new EnrichmentFailure(new Stm32MappingException(
                DiagnosticCode.PACK_APPLICATION_FAILED,
                "SVD address is outside the program address space", exception));
        }
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

        private final String exactPart;

        private final TaskMonitor monitor;

        private final List<Stm32DeviceDataReport.Block> blocks = new ArrayList<>();

        private final List<Stm32DeviceDataReport.Symbol> symbols = new ArrayList<>();

        private final List<Long> dataAddresses = new ArrayList<>();

        private final List<Stm32DeviceDataReport.Conflict> conflicts = new ArrayList<>();

        private Stm32SvdPack pack;

        private Stm32InterruptPlan.Entry interrupts;

        private String core;

        private int comments;

        private int enumerations;

        private int interruptCount;

        private Context(Program program, String exactPart, TaskMonitor monitor) {
            this.program = program;
            this.exactPart = exactPart;
            this.monitor = monitor;
        }

        private io.github.rezabakhshi.embedra.svd.Stm32SvdDevice device() {
            return pack.device();
        }

        private CategoryPath category() {
            return new CategoryPath("/Embedra/" + safe(exactPart) + "/SVD");
        }

        private Stm32DeviceDataReport report() {
            return new Stm32DeviceDataReport(true, exactPart, core,
                pack == null ? null : pack.manifest().packId(),
                pack == null ? null : pack.manifest().contentDigest(),
                pack == null ? null : pack.sourceFile(),
                pack == null ? null : pack.sourceFileSha256(),
                blocks, symbols, dataAddresses, comments, enumerations,
                pack == null ? 0 : Math.toIntExact(pack.registerCount()),
                interruptCount, conflicts);
        }
    }
}
