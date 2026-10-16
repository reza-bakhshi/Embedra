package io.github.rezabakhshi.embedra.ghidra.atmel;

import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.ghidra.atmel.AtmelInputDecoder.DecodedAtmelFirmware;
import io.github.rezabakhshi.embedra.ghidra.atmel.AtmelInputDecoder.DecodedSegment;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryPlan;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryRegion;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelIoPort;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelPeripheral;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelPeripheralPack;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelPeripheralSchemaTransform;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelRegister;
import io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorEntry;
import io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorTable;
import java.io.ByteArrayInputStream;
import java.util.Objects;

/**
 * Maps pure Atmel / Microchip memory layouts, vector tables, and peripheral packs into Ghidra programs.
 */
public final class AtmelFirmwareMapper {

    public static final String OPTIONS_CATEGORY = "Embedra Atmel Firmware";

    public AtmelImportReport map(
            Program program,
            AtmelPartRecord part,
            AtmelMemoryPlan memoryPlan,
            AtmelVectorTable vectorTable,
            AtmelPeripheralPack peripheralPack,
            DecodedAtmelFirmware decoded,
            TaskMonitor monitor) throws AtmelMappingException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(memoryPlan, "memoryPlan must not be null");
        Objects.requireNonNull(decoded, "decoded must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        monitor.checkCancelled();

        // 1. Language binding verification
        String actualLanguage = program.getLanguageID().getIdAsString().toUpperCase();
        if (decoded.isAvr()) {
            if (!actualLanguage.startsWith("AVR8")) {
                throw new AtmelMappingException(
                    DiagnosticCode.ATMEL_LANGUAGE_MISMATCH,
                    String.format("Program language (%s) is not an AVR8 processor language definition",
                        actualLanguage)
                );
            }
        } else {
            if (!actualLanguage.startsWith("ARM:LE:32")) {
                throw new AtmelMappingException(
                    DiagnosticCode.ATMEL_LANGUAGE_MISMATCH,
                    String.format(
                        "Program language (%s) is not a 32-bit little-endian ARM processor language definition",
                        actualLanguage)
                );
            }
        }

        int blocksCreated = 0;
        int registersApplied = 0;

        // Transactional mutation with clean rollback on failure
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Map Embedra Atmel firmware layout")) {

            Memory memory = program.getMemory();
            AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
            AddressSpace codeSpace = program.getAddressFactory().getAddressSpace("code");
            if (codeSpace == null) {
                codeSpace = defaultSpace;
            }

            // 2. Map initialized firmware segments from decoded input
            for (DecodedSegment seg : decoded.segments()) {
                monitor.checkCancelled();
                AddressSpace segSpace = part.isAvr() ? codeSpace : defaultSpace;
                long unitSize = segSpace.getAddressableUnitSize();
                Address segAddr = segSpace.getAddress(seg.address() / unitSize);

                if (findBlock(memory, segAddr) == null) {
                    try {
                        MemoryBlock block = memory.createInitializedBlock(
                            seg.name(), segAddr, new ByteArrayInputStream(seg.data()),
                            seg.data().length, monitor, false
                        );
                        block.setRead(true);
                        block.setWrite(false);
                        block.setExecute(true);
                        blocksCreated++;
                    } catch (Exception e) {
                        throw new AtmelMappingException(
                            DiagnosticCode.ATMEL_MAPPING_FAILED,
                            "Failed to create initialized memory block " + seg.name() + " at 0x"
                                + Long.toHexString(seg.address()) + ": " + e.getMessage(), e);
                    }
                }
            }

            // 3. Map uninitialized target memory regions from plan
            for (AtmelMemoryRegion region : memoryPlan.regions()) {
                monitor.checkCancelled();
                AddressSpace targetSpace = resolveAddressSpace(program, region.addressSpace());
                if (targetSpace == null) {
                    continue;
                }
                long unitSize = targetSpace.getAddressableUnitSize();
                long offset = region.start() / unitSize;
                if (offset > targetSpace.getMaxAddress().getOffset()
                        || offset < targetSpace.getMinAddress().getOffset()) {
                    continue;
                }
                Address regionAddr;
                try {
                    regionAddr = targetSpace.getAddress(offset);
                } catch (Exception e) {
                    continue;
                }

                if (!overlaps(memory, regionAddr, region.length() / unitSize)) {
                    createUninitializedBlock(
                        memory,
                        region.name(),
                        regionAddr,
                        region.length(),
                        region.read(),
                        region.write(),
                        region.execute(),
                        region.isVolatile()
                    );
                    blocksCreated++;
                }
            }

            // 4. Vector table symbols and entry points
            if (vectorTable != null) {
                applyVectorTable(program, part, vectorTable, codeSpace, defaultSpace);
            }

            // 5. Bootloader entry points
            if (decoded.bootloaderAddress().isPresent()) {
                long bootAddr = decoded.bootloaderAddress().get();
                if (bootAddr == 0x00007E00L) {
                    Address optiAddr = part.isAvr()
                        ? codeSpace.getAddress(bootAddr / 2L)
                        : defaultSpace.getAddress(bootAddr);
                    createLabelSafe(program, optiAddr, "Optiboot_Reset_Handler", true);
                    try {
                        program.getSymbolTable().addExternalEntryPoint(optiAddr);
                    } catch (Exception ignored) {
                    }
                } else if (bootAddr == 0x00800000L) {
                    Address sambaAddr = defaultSpace.getAddress(bootAddr);
                    createLabelSafe(program, sambaAddr, "SAMBA_Reset_Handler", true);
                    try {
                        program.getSymbolTable().addExternalEntryPoint(sambaAddr);
                    } catch (Exception ignored) {
                    }
                }
            }

            // 6. Apply peripheral pack registers, comments, and schemas
            if (peripheralPack != null) {
                registersApplied = applyPeripheralPack(program, peripheralPack, monitor);
            }

            // 7. Embedra Atmel Program Options
            Options options = program.getOptions(OPTIONS_CATEGORY);
            options.setString("Target Silicon Part", part.exactPart());
            options.setString("Family", part.family());
            options.setString("Series", part.series());
            options.setString("Core Architecture", part.core());
            options.setString("Address Model", part.addressModel().name());
            options.setLong("Flash Base", part.flashStart());
            options.setLong("Flash Bytes", part.flashBytes());
            options.setLong("RAM Base", part.ramStart());
            options.setLong("RAM Bytes", part.ramBytes());
            options.setString("Input Format", decoded.format());
            options.setString("Import Status", "SUCCESS");

            transaction.commit();

            return new AtmelImportReport(
                part.exactPart(),
                part.family(),
                part.series(),
                decoded.format(),
                program.getLanguageID().getIdAsString(),
                program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
                decoded.entryPoint(),
                part.flashStart(),
                part.flashBytes(),
                blocksCreated,
                registersApplied,
                true,
                "Imported successfully"
            );
        } catch (AtmelMappingException | CancelledException e) {
            throw e;
        } catch (Exception e) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_MAPPING_FAILED,
                "Transaction aborted during Atmel firmware mapping: " + e.getMessage(), e);
        }
    }

    private void applyVectorTable(
            Program program,
            AtmelPartRecord part,
            AtmelVectorTable vectorTable,
            AddressSpace codeSpace,
            AddressSpace defaultSpace) {
        long resetTarget = vectorTable.resetEntry().map(AtmelVectorEntry::targetAddress).orElse(0L);
        if (part.isAvr()) {
            Address entryAddr = codeSpace.getAddress(resetTarget / 2L);
            createLabelSafe(program, entryAddr, "Reset_Handler", true);
            try {
                program.getSymbolTable().addExternalEntryPoint(entryAddr);
            } catch (Exception ignored) {
            }

            for (AtmelVectorEntry entry : vectorTable.entries()) {
                Address slotAddr = codeSpace.getAddress(entry.entryAddress() / 2L);
                try {
                    program.getListing().setComment(
                        slotAddr, CommentType.EOL,
                        String.format("Vector Slot %d: %s -> 0x%04X (%s)",
                            entry.slot().index(), entry.slot().name(),
                            entry.targetAddress(), entry.canonicalLabel())
                    );
                } catch (Exception ignored) {
                }

                if (entry.isValid() && entry.targetAddress() > 0 && !entry.isReset()) {
                    Address targetAddr = codeSpace.getAddress(entry.targetAddress() / 2L);
                    createLabelSafe(program, targetAddr, entry.canonicalLabel(), false);
                }
            }
        } else {
            Address entryAddr = defaultSpace.getAddress(resetTarget);
            createLabelSafe(program, entryAddr, "Reset_Handler", true);
            try {
                program.getSymbolTable().addExternalEntryPoint(entryAddr);
            } catch (Exception ignored) {
            }

            for (AtmelVectorEntry entry : vectorTable.entries()) {
                Address slotAddr = defaultSpace.getAddress(entry.entryAddress());
                try {
                    program.getListing().setComment(
                        slotAddr, CommentType.EOL,
                        String.format("Vector Slot %d: %s -> 0x%08X (%s)",
                            entry.slot().index(), entry.slot().name(),
                            entry.targetAddress(), entry.canonicalLabel())
                    );
                } catch (Exception ignored) {
                }

                if (entry.isValid() && entry.targetAddress() > 0 && !entry.isReset()) {
                    Address targetAddr = defaultSpace.getAddress(entry.targetAddress());
                    createLabelSafe(program, targetAddr, entry.canonicalLabel(), false);
                }
            }
        }
    }

    private static void createLabelSafe(Program program, Address addr, String name, boolean makePrimary) {
        try {
            Symbol s = program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
            if (makePrimary && s != null) {
                s.setPrimary();
            }
        } catch (Exception ignored) {
        }
    }

    private int applyPeripheralPack(
            Program program,
            AtmelPeripheralPack peripheralPack,
            TaskMonitor monitor) throws CancelledException {
        int applied = 0;
        Memory memory = program.getMemory();

        for (AtmelPeripheral periph : peripheralPack.peripherals()) {
            monitor.checkCancelled();
            Address baseAddr = resolveAddress(program, periph.addressSpace(), periph.baseAddress());
            if (baseAddr != null && memory.contains(baseAddr)) {
                try {
                    program.getListing().setComment(
                        baseAddr, CommentType.PLATE,
                        AtmelPeripheralSchemaTransform.formatPeripheralPlateComment(periph)
                    );
                } catch (Exception ignored) {
                }
            }

            for (AtmelRegister reg : periph.registers()) {
                Address regAddr = resolveAddress(program, periph.addressSpace(), reg.address());
                if (regAddr != null && memory.contains(regAddr)) {
                    try {
                        if (program.getSymbolTable().getPrimarySymbol(regAddr) == null) {
                            program.getSymbolTable().createLabel(regAddr, reg.name(), SourceType.IMPORTED);
                        }
                        program.getListing().setComment(
                            regAddr, CommentType.EOL,
                            AtmelPeripheralSchemaTransform.formatRegisterComment(reg)
                        );
                        applied++;
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        for (AtmelIoPort ioPort : peripheralPack.ioPorts()) {
            AtmelRegister reg = findRegisterByName(peripheralPack, ioPort.dataRegister());
            if (reg != null) {
                Address portAddr = resolveAddress(program, "mem", reg.address());
                if (portAddr != null && memory.contains(portAddr)) {
                    try {
                        program.getListing().setComment(
                            portAddr, CommentType.PLATE,
                            AtmelPeripheralSchemaTransform.formatIoPortComment(ioPort)
                        );
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        return applied;
    }

    private static AtmelRegister findRegisterByName(AtmelPeripheralPack pack, String regName) {
        if (regName == null || regName.isBlank()) {
            return null;
        }
        for (AtmelPeripheral periph : pack.peripherals()) {
            for (AtmelRegister reg : periph.registers()) {
                if (reg.name().equalsIgnoreCase(regName)) {
                    return reg;
                }
            }
        }
        return null;
    }

    private static Address resolveAddress(Program program, String spaceName, long byteOffset) {
        AddressSpace space = resolveAddressSpace(program, spaceName);
        if (space == null) {
            return null;
        }
        long unitSize = space.getAddressableUnitSize();
        long offset = byteOffset / unitSize;
        if (offset > space.getMaxAddress().getOffset() || offset < space.getMinAddress().getOffset()) {
            return null;
        }
        try {
            return space.getAddress(offset);
        } catch (Exception e) {
            return null;
        }
    }

    private static AddressSpace resolveAddressSpace(Program program, String spaceName) {
        if (spaceName == null || spaceName.isBlank()) {
            return program.getAddressFactory().getDefaultAddressSpace();
        }
        AddressSpace space = program.getAddressFactory().getAddressSpace(spaceName);
        if (space != null) {
            return space;
        }
        if ("data".equalsIgnoreCase(spaceName)) {
            space = program.getAddressFactory().getAddressSpace("mem");
            if (space != null) {
                return space;
            }
        }
        if ("code".equalsIgnoreCase(spaceName)) {
            return program.getAddressFactory().getDefaultAddressSpace();
        }
        return program.getAddressFactory().getDefaultAddressSpace();
    }

    private static MemoryBlock findBlock(Memory memory, Address addr) {
        return memory.getBlock(addr);
    }

    private static boolean overlaps(Memory memory, Address startAddr, long length) {
        if (length <= 0) {
            return false;
        }
        try {
            Address endAddr = startAddr.addNoWrap(length - 1L);
            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.getStart().getAddressSpace().equals(startAddr.getAddressSpace())) {
                    continue;
                }
                Address bStart = block.getStart();
                Address bEnd = block.getEnd();
                if (startAddr.compareTo(bEnd) <= 0 && bStart.compareTo(endAddr) <= 0) {
                    return true;
                }
            }
        } catch (Exception e) {
            return true;
        }
        return false;
    }

    private static void createUninitializedBlock(
            Memory memory,
            String name,
            Address start,
            long sizeBytes,
            boolean read,
            boolean write,
            boolean execute,
            boolean isVolatile) throws Exception {
        if (sizeBytes <= 0) {
            return;
        }
        long unitSize = start.getAddressSpace().getAddressableUnitSize();
        long units = sizeBytes / unitSize;
        MemoryBlock block = memory.createUninitializedBlock(name, start, units, false);
        block.setRead(read);
        block.setWrite(write);
        block.setExecute(execute);
        block.setVolatile(isVolatile);
    }
}
