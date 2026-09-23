package io.github.rezabakhshi.embedra.ghidra.esp;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
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
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.pack.EspSvdPack;
import io.github.rezabakhshi.embedra.svd.EspSvdField;
import io.github.rezabakhshi.embedra.svd.EspSvdEnumeratedValue;
import io.github.rezabakhshi.embedra.svd.EspSvdPeripheral;
import io.github.rezabakhshi.embedra.svd.EspSvdRegister;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** Applies ESP32-S3 SVD blocks, labels, field types, and descriptions safely. */
public final class Esp32S3SvdApplicator {
    private static final CategoryPath CATEGORY = new CategoryPath("/Embedra/ESP32-S3/SVD");

    public EspSvdApplicationReport apply(Program program, EspSvdPack pack,
            TaskMonitor monitor) throws EspMappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(pack, "pack");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        if (!pack.manifest().supportedDevices().equals(List.of("esp32s3"))
            || !pack.device().name().equals("ESP32-S3")) {
            throw new EspMappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "SVD pack identity is not ESP32-S3");
        }
        List<EspCreatedBlock> blocks = new ArrayList<>();
        List<EspAppliedSymbol> symbols = new ArrayList<>();
        List<Long> dataAddresses = new ArrayList<>();
        List<EspPackConflict> conflicts = new ArrayList<>();
        int comments = 0;
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply verified ESP32-S3 SVD enrichment")) {
            for (EspSvdPeripheral peripheral : pack.device().peripherals()) {
                monitor.checkCancelled();
                ensureBlock(program, peripheral, blocks, conflicts);
                applyLabel(program, peripheral.name(), peripheral.baseAddress(), symbols,
                    conflicts);
                comments += applyComment(program, peripheral.baseAddress(),
                    peripheral.description());
                for (EspSvdRegister register : peripheral.registers()) {
                    monitor.checkCancelled();
                    String label = registerLabel(peripheral.name(), register.name());
                    applyLabel(program, label, register.address(), symbols, conflicts);
                    applyType(program, peripheral, register, dataAddresses, conflicts);
                    comments += applyComment(program, register.address(),
                        register.description());
                }
            }
            recordIdentity(program, pack);
            transaction.commit();
        }
        catch (LockException | MemoryConflictException | AddressOverflowException
                | InvalidInputException | CodeUnitInsertionException
                | InvalidDataTypeException exception) {
            throw new EspMappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected verified ESP32-S3 SVD enrichment", exception);
        }
        return new EspSvdApplicationReport(true, pack.manifest().contentDigest(), blocks,
            symbols, dataAddresses, comments, conflicts);
    }

    private static void ensureBlock(Program program, EspSvdPeripheral peripheral,
            List<EspCreatedBlock> created, List<EspPackConflict> conflicts)
            throws EspMappingException, LockException, MemoryConflictException,
            AddressOverflowException {
        String name = "embedra_svd_" + safeName(peripheral.name()).toLowerCase(Locale.ROOT);
        Address start = address(program, peripheral.baseAddress());
        Address end = address(program, peripheral.endExclusive() - 1);
        MemoryBlock named = program.getMemory().getBlock(name);
        if (named != null && named.getStart().equals(start) && named.getEnd().equals(end)
            && named.isRead() && named.isWrite() && named.isVolatile()) {
            return;
        }
        for (MemoryBlock existing : program.getMemory().getBlocks()) {
            if (start.compareTo(existing.getEnd()) <= 0
                && existing.getStart().compareTo(end) <= 0) {
                conflicts.add(new EspPackConflict(peripheral.baseAddress(),
                    "MEMORY_PRESERVED", "Existing block " + existing.getName()
                        + " was not overwritten by SVD data"));
                return;
            }
        }
        long length = peripheral.endExclusive() - peripheral.baseAddress();
        MemoryBlock block = program.getMemory().createUninitializedBlock(name, start,
            length, false);
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(false);
        block.setVolatile(true);
        created.add(new EspCreatedBlock(name, peripheral.baseAddress(), length));
    }

    private static void applyLabel(Program program, String name, long offset,
            List<EspAppliedSymbol> created, List<EspPackConflict> conflicts)
            throws EspMappingException, InvalidInputException {
        Address target = address(program, offset);
        if (program.getMemory().getBlock(target) == null) {
            conflicts.add(new EspPackConflict(offset, "UNMAPPED_SYMBOL",
                "SVD symbol address is not mapped: " + name));
            return;
        }
        for (Symbol symbol : program.getSymbolTable().getSymbols(target)) {
            if (symbol.getName().equals(name)) {
                return;
            }
        }
        if (program.getSymbolTable().getSymbols(name).hasNext()) {
            conflicts.add(new EspPackConflict(offset, "NAME_CONFLICT",
                "SVD symbol name already exists elsewhere: " + name));
            return;
        }
        Symbol primary = program.getSymbolTable().getPrimarySymbol(target);
        Symbol imported = program.getSymbolTable().createLabel(target, name,
            SourceType.IMPORTED);
        if (primary != null && imported.isPrimary()) {
            primary.setPrimary();
        }
        created.add(new EspAppliedSymbol(name, offset, false));
    }

    private static void applyType(Program program, EspSvdPeripheral peripheral,
            EspSvdRegister register, List<Long> created,
            List<EspPackConflict> conflicts) throws EspMappingException,
            CodeUnitInsertionException, InvalidDataTypeException {
        Address target = address(program, register.address());
        if (program.getMemory().getBlock(target) == null) {
            return;
        }
        DataType proposed = registerType(program, peripheral, register);
        Data existing = program.getListing().getDefinedDataAt(target);
        if (existing != null) {
            if (!existing.getDataType().isEquivalent(proposed)) {
                conflicts.add(new EspPackConflict(register.address(), "TYPE_PRESERVED",
                    "Existing data type was not overwritten by SVD data"));
            }
            return;
        }
        if (program.getListing().getInstructionAt(target) != null) {
            conflicts.add(new EspPackConflict(register.address(),
                "INSTRUCTION_PRESERVED", "Existing instruction was not overwritten"));
            return;
        }
        program.getListing().createData(target, proposed);
        created.add(register.address());
    }

    private static DataType registerType(Program program, EspSvdPeripheral peripheral,
            EspSvdRegister register) throws InvalidDataTypeException {
        if (register.sizeBits() != 32 || register.fields().isEmpty()) {
            return DWordDataType.dataType;
        }
        String typeName = registerLabel(peripheral.name(), register.name()) + "_t";
        StructureDataType structure = new StructureDataType(CATEGORY, typeName, 4,
            program.getDataTypeManager());
        for (EspSvdField field : register.fields()) {
            DataType fieldType = fieldType(program, typeName, field);
            structure.insertBitFieldAt(0, 4, field.bitOffset(),
                fieldType, field.bitWidth(), safeName(field.name()),
                field.description().isBlank() ? null : field.description());
        }
        return program.getDataTypeManager().resolve(structure,
            DataTypeConflictHandler.KEEP_HANDLER);
    }

    private static DataType fieldType(Program program, String registerType,
            EspSvdField field) {
        if (field.enumeratedValues().isEmpty()) {
            return UnsignedIntegerDataType.dataType;
        }
        EnumDataType enumeration = new EnumDataType(CATEGORY,
            registerType + "_" + safeName(field.name()) + "_e", 4,
            program.getDataTypeManager());
        for (EspSvdEnumeratedValue value : field.enumeratedValues()) {
            enumeration.add(safeName(value.name()), value.value(),
                value.description().isBlank() ? null : value.description());
        }
        return program.getDataTypeManager().resolve(enumeration,
            DataTypeConflictHandler.KEEP_HANDLER);
    }

    private static int applyComment(Program program, long offset, String description)
            throws EspMappingException {
        if (description.isBlank()) {
            return 0;
        }
        Address target = address(program, offset);
        if (program.getMemory().getBlock(target) == null
            || program.getListing().getComment(CommentType.EOL, target) != null) {
            return 0;
        }
        program.getListing().setComment(target, CommentType.EOL,
            "Embedra SVD: " + description);
        return 1;
    }

    private static void recordIdentity(Program program, EspSvdPack pack) {
        var options = program.getOptions("Embedra ESP32-S3 SVD");
        options.setString("Pack ID", pack.manifest().packId());
        options.setString("Pack Version", pack.manifest().version().toString());
        options.setString("Pack Digest", pack.manifest().contentDigest());
        options.setString("Source Revision", pack.device().sourceRevision());
        options.setLong("Matched Peripheral Bases",
            pack.reconciliation().matchingPeripheralBases());
        options.setLong("Matched Register Addresses",
            pack.reconciliation().matchingRegisterAddresses());
    }

    private static String registerLabel(String peripheral, String register) {
        return safeName(peripheral + "_" + register + "_REG");
    }

    private static String safeName(String value) {
        return value.replaceAll("[^A-Za-z0-9_$]", "_");
    }

    private static Address address(Program program, long offset)
            throws EspMappingException {
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        catch (RuntimeException exception) {
            throw new EspMappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "SVD address is outside the program address space", exception);
        }
    }
}
