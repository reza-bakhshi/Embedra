package io.github.rezabakhshi.embedra.ghidra.esp;

import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.pack.EspPeripheral;
import io.github.rezabakhshi.embedra.pack.EspPeripheralPack;
import io.github.rezabakhshi.embedra.pack.EspPeripheralRegister;
import io.github.rezabakhshi.embedra.pack.EspRomSymbol;
import io.github.rezabakhshi.embedra.pack.EspRomSymbolKind;
import io.github.rezabakhshi.embedra.pack.EspRomSymbolPack;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/** Transactional, idempotent, user-preserving application of ESP32-S3 packs. */
public final class Esp32S3PackApplicator {
    private static final long ROM_CODE_START = 0x4000_0000L;

    private static final long ROM_CODE_LENGTH = 0x60000L;

    public EspPackApplicationReport apply(Program program, EspRomSymbolPack rom,
            EspPeripheralPack peripherals, TaskMonitor monitor)
            throws EspMappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(rom, "rom");
        Objects.requireNonNull(peripherals, "peripherals");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        if (!rom.deviceId().equals("esp32s3")
            || !peripherals.deviceId().equals("esp32s3")) {
            throw new EspMappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "Pack device identity is not ESP32-S3");
        }

        List<EspCreatedBlock> blocks = new ArrayList<>();
        List<EspAppliedSymbol> symbols = new ArrayList<>();
        List<Long> dataAddresses = new ArrayList<>();
        List<EspPackConflict> conflicts = new ArrayList<>();
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply verified ESP32-S3 enrichment packs")) {
            ensureBlock(program, new BlockPlan("embedra_esp32s3_rom_code",
                ROM_CODE_START, ROM_CODE_LENGTH, true, false, true, false),
                blocks, conflicts);
            for (long address : romDataAddresses(rom)) {
                monitor.checkCancelled();
                ensureBlock(program, new BlockPlan(String.format(Locale.ROOT,
                    "embedra_rom_data_%08x", address), address, 4,
                    true, false, false, false), blocks, conflicts);
            }
            for (EspPeripheral peripheral : peripherals.peripherals()) {
                monitor.checkCancelled();
                ensureBlock(program, new BlockPlan("embedra_peripheral_"
                    + safeBlockName(peripheral.name()), peripheral.baseAddress(),
                    peripheral.endExclusive() - peripheral.baseAddress(),
                    true, true, false, true), blocks, conflicts);
            }

            for (EspRomSymbol symbol : rom.symbols()) {
                monitor.checkCancelled();
                applyRomSymbol(program, symbol, symbols, conflicts);
            }
            for (EspPeripheral peripheral : peripherals.peripherals()) {
                monitor.checkCancelled();
                applyLabel(program, peripheral.name(), peripheral.baseAddress(), false,
                    symbols, conflicts);
                for (String alias : peripheral.aliases()) {
                    applyLabel(program, alias, peripheral.baseAddress(), false,
                        symbols, conflicts);
                }
                for (EspPeripheralRegister register : peripheral.registers()) {
                    monitor.checkCancelled();
                    for (String name : register.names()) {
                        applyLabel(program, name, register.address(), false,
                            symbols, conflicts);
                    }
                    applyRegisterType(program, register.address(), dataAddresses,
                        conflicts);
                }
            }
            recordPackIdentity(program, rom, peripherals);
            transaction.commit();
        }
        catch (LockException | MemoryConflictException | AddressOverflowException
                | InvalidInputException | CodeUnitInsertionException
                | OverlappingFunctionException exception) {
            throw new EspMappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected verified ESP32-S3 enrichment", exception);
        }
        return new EspPackApplicationReport(true, rom.manifest().contentDigest(),
            peripherals.manifest().contentDigest(), blocks, symbols, dataAddresses,
            conflicts);
    }

    public EspPackRemovalReport remove(Program program,
            EspPackApplicationReport receipt, TaskMonitor monitor)
            throws EspMappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(receipt, "receipt");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        List<EspPackConflict> conflicts = new ArrayList<>();
        int removedSymbols = 0;
        int removedData = 0;
        int removedBlocks = 0;
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Remove receipt-scoped ESP32-S3 enrichment")) {
            for (EspAppliedSymbol applied : receipt.createdSymbols()) {
                monitor.checkCancelled();
                if (applied.function()) {
                    Function function = program.getFunctionManager().getFunctionAt(
                        address(program, applied.address()));
                    if (function != null && function.getName().equals(applied.name())) {
                        if (program.getFunctionManager().removeFunction(
                                function.getEntryPoint())) {
                            removedSymbols++;
                        }
                    }
                }
            }
            for (EspAppliedSymbol applied : receipt.createdSymbols()) {
                monitor.checkCancelled();
                Symbol symbol = importedSymbol(program, applied.name(), applied.address());
                if (symbol != null && symbol.delete()) {
                    removedSymbols++;
                }
            }
            for (long offset : receipt.createdDataAddresses()) {
                monitor.checkCancelled();
                Address start = address(program, offset);
                Data data = program.getListing().getDefinedDataAt(start);
                if (data != null && data.getDataType().isEquivalent(DWordDataType.dataType)) {
                    program.getListing().clearCodeUnits(start, start.add(3), false);
                    removedData++;
                }
                else if (data != null) {
                    conflicts.add(new EspPackConflict(offset, "DATA_CHANGED",
                        "Register data type was changed after pack application"));
                }
            }
            List<EspCreatedBlock> reverseBlocks = new ArrayList<>(receipt.createdBlocks());
            reverseBlocks.sort(Comparator.comparingLong(EspCreatedBlock::start).reversed());
            for (EspCreatedBlock created : reverseBlocks) {
                monitor.checkCancelled();
                MemoryBlock block = program.getMemory().getBlock(created.name());
                if (block == null) {
                    continue;
                }
                if (!matches(block, created) || hasUserArtifacts(program, block)) {
                    conflicts.add(new EspPackConflict(created.start(), "BLOCK_CHANGED",
                        "Enrichment block was changed or contains user artifacts"));
                    continue;
                }
                program.getMemory().removeBlock(block, monitor);
                removedBlocks++;
            }
            transaction.commit();
        }
        catch (LockException exception) {
            throw new EspMappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "Ghidra rejected receipt-scoped pack removal", exception);
        }
        return new EspPackRemovalReport(true, removedBlocks, removedSymbols,
            removedData, conflicts);
    }

    private static void ensureBlock(Program program, BlockPlan plan,
            List<EspCreatedBlock> created, List<EspPackConflict> conflicts)
            throws LockException, MemoryConflictException, AddressOverflowException,
            EspMappingException {
        Address start = address(program, plan.start());
        Address end = address(program, plan.start() + plan.length() - 1);
        MemoryBlock named = program.getMemory().getBlock(plan.name());
        if (named != null && named.getStart().equals(start) && named.getEnd().equals(end)
            && named.isRead() == plan.read() && named.isWrite() == plan.write()
            && named.isExecute() == plan.execute()
            && named.isVolatile() == plan.volatileBlock()) {
            return;
        }
        for (MemoryBlock existing : program.getMemory().getBlocks()) {
            if (overlaps(start, end, existing)) {
                conflicts.add(new EspPackConflict(plan.start(), "MEMORY_PRESERVED",
                    "Existing block " + existing.getName() + " was not overwritten"));
                return;
            }
        }
        MemoryBlock block = program.getMemory().createUninitializedBlock(plan.name(), start,
            plan.length(), false);
        block.setRead(plan.read());
        block.setWrite(plan.write());
        block.setExecute(plan.execute());
        block.setVolatile(plan.volatileBlock());
        created.add(new EspCreatedBlock(plan.name(), plan.start(), plan.length()));
    }

    private static void applyRomSymbol(Program program, EspRomSymbol symbol,
            List<EspAppliedSymbol> created, List<EspPackConflict> conflicts)
            throws InvalidInputException, OverlappingFunctionException,
            EspMappingException {
        Address target = address(program, symbol.address());
        if (program.getMemory().getBlock(target) == null) {
            conflicts.add(new EspPackConflict(symbol.address(), "UNMAPPED_SYMBOL",
                "ROM symbol address has no preserved or pack-created memory"));
            return;
        }
        Symbol existingAtAddress = namedSymbol(program, symbol.name(), target);
        if (existingAtAddress != null) {
            return;
        }
        if (nameExistsElsewhere(program, symbol.name(), target)) {
            conflicts.add(new EspPackConflict(symbol.address(), "NAME_CONFLICT",
                "Symbol name already exists at another address: " + symbol.name()));
            return;
        }
        Symbol primary = program.getSymbolTable().getPrimarySymbol(target);
        if (symbol.kind() == EspRomSymbolKind.FUNCTION && primary == null
            && program.getFunctionManager().getFunctionAt(target) == null) {
            program.getFunctionManager().createFunction(symbol.name(), target,
                new AddressSet(target, target), SourceType.IMPORTED);
            created.add(new EspAppliedSymbol(symbol.name(), symbol.address(), true));
            return;
        }
        applyLabel(program, symbol.name(), symbol.address(), false, created, conflicts);
    }

    private static void applyLabel(Program program, String name, long offset,
            boolean function, List<EspAppliedSymbol> created,
            List<EspPackConflict> conflicts) throws InvalidInputException,
            EspMappingException {
        Address target = address(program, offset);
        if (program.getMemory().getBlock(target) == null) {
            conflicts.add(new EspPackConflict(offset, "UNMAPPED_SYMBOL",
                "Pack symbol address is not mapped: " + name));
            return;
        }
        if (namedSymbol(program, name, target) != null) {
            return;
        }
        if (nameExistsElsewhere(program, name, target)) {
            conflicts.add(new EspPackConflict(offset, "NAME_CONFLICT",
                "Symbol name already exists at another address: " + name));
            return;
        }
        Symbol primary = program.getSymbolTable().getPrimarySymbol(target);
        Symbol imported = program.getSymbolTable().createLabel(target, name,
            SourceType.IMPORTED);
        if (primary != null && imported.isPrimary()) {
            primary.setPrimary();
        }
        created.add(new EspAppliedSymbol(name, offset, function));
    }

    private static void applyRegisterType(Program program, long offset,
            List<Long> created, List<EspPackConflict> conflicts)
            throws CodeUnitInsertionException, EspMappingException {
        Address target = address(program, offset);
        Data existing = program.getListing().getDefinedDataAt(target);
        if (existing != null) {
            if (!existing.getDataType().isEquivalent(DWordDataType.dataType)) {
                conflicts.add(new EspPackConflict(offset, "TYPE_PRESERVED",
                    "Existing user data type was not overwritten"));
            }
            return;
        }
        if (program.getListing().getInstructionAt(target) != null) {
            conflicts.add(new EspPackConflict(offset, "INSTRUCTION_PRESERVED",
                "Existing instruction was not overwritten"));
            return;
        }
        if (program.getMemory().getBlock(target) != null) {
            program.getListing().createData(target, DWordDataType.dataType);
            created.add(offset);
        }
    }

    private static void recordPackIdentity(Program program, EspRomSymbolPack rom,
            EspPeripheralPack peripherals) {
        var options = program.getOptions("Embedra ESP32-S3 Packs");
        options.setString("ROM Pack ID", rom.manifest().packId());
        options.setString("ROM Pack Version", rom.manifest().version().toString());
        options.setString("ROM Pack Digest", rom.manifest().contentDigest());
        options.setString("Peripheral Pack ID", peripherals.manifest().packId());
        options.setString("Peripheral Pack Version",
            peripherals.manifest().version().toString());
        options.setString("Peripheral Pack Digest",
            peripherals.manifest().contentDigest());
    }

    private static List<Long> romDataAddresses(EspRomSymbolPack rom) {
        return rom.symbols().stream()
            .filter(symbol -> symbol.kind() == EspRomSymbolKind.DATA)
            .map(EspRomSymbol::address).distinct().sorted().toList();
    }

    private static String safeBlockName(String name) {
        return name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_]+", "_");
    }

    private static boolean overlaps(Address start, Address end, MemoryBlock block) {
        return start.getAddressSpace().equals(block.getStart().getAddressSpace())
            && start.compareTo(block.getEnd()) <= 0
            && block.getStart().compareTo(end) <= 0;
    }

    private static boolean matches(MemoryBlock block, EspCreatedBlock created) {
        return block.getStart().getOffset() == created.start()
            && block.getSize() == created.length() && !block.isInitialized();
    }

    private static boolean hasUserArtifacts(Program program, MemoryBlock block) {
        AddressSet range = new AddressSet(block.getStart(), block.getEnd());
        SymbolIterator labels = program.getSymbolTable().getSymbols(
            range, SymbolType.LABEL, true);
        SymbolIterator functions = program.getSymbolTable().getSymbols(
            range, SymbolType.FUNCTION, true);
        if (labels.hasNext() || functions.hasNext()
            || program.getListing().getDefinedData(range, true).hasNext()
            || program.getListing().getInstructions(range, true).hasNext()) {
            return true;
        }
        var bookmarks = program.getBookmarkManager().getBookmarksIterator(
            block.getStart(), true);
        return bookmarks.hasNext()
            && bookmarks.next().getAddress().compareTo(block.getEnd()) <= 0;
    }

    private static Symbol namedSymbol(Program program, String name, Address address) {
        for (Symbol symbol : program.getSymbolTable().getSymbols(address)) {
            if (symbol.getName().equals(name)) {
                return symbol;
            }
        }
        return null;
    }

    private static boolean nameExistsElsewhere(Program program, String name,
            Address expected) {
        SymbolIterator symbols = program.getSymbolTable().getSymbols(name);
        while (symbols.hasNext()) {
            if (!symbols.next().getAddress().equals(expected)) {
                return true;
            }
        }
        return false;
    }

    private static Symbol importedSymbol(Program program, String name, long offset)
            throws EspMappingException {
        Symbol symbol = namedSymbol(program, name, address(program, offset));
        return symbol != null && symbol.getSource() == SourceType.IMPORTED ? symbol : null;
    }

    private static Address address(Program program, long offset)
            throws EspMappingException {
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        catch (RuntimeException exception) {
            throw new EspMappingException(DiagnosticCode.PACK_APPLICATION_FAILED,
                "Pack address is outside the program address space", exception);
        }
    }

    private record BlockPlan(
            String name,
            long start,
            long length,
            boolean read,
            boolean write,
            boolean execute,
            boolean volatileBlock) {
    }
}
