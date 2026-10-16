package io.github.rezabakhshi.embedra.ghidra.nordic;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.ghidra.nordic.NordicInputDecoder.DecodedNordicFirmware;
import io.github.rezabakhshi.embedra.ghidra.nordic.NordicInputDecoder.DecodedSegment;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import io.github.rezabakhshi.embedra.targets.nordic.memory.NordicMemoryPlan;
import io.github.rezabakhshi.embedra.targets.nordic.memory.NordicMemoryRegion;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicPeripheral;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicPeripheralPack;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicPeripheralSchemaTransform;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicRegister;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Maps pure Nordic Semiconductor memory layouts, vector tables, and peripheral packs into Ghidra programs.
 */
public final class NordicFirmwareMapper {

    public static final String OPTIONS_CATEGORY = "Embedra Nordic Firmware";

    public NordicImportReport map(
            Program program,
            NordicPartRecord part,
            NordicMemoryPlan memoryPlan,
            NordicPeripheralPack peripheralPack,
            DecodedNordicFirmware decoded,
            TaskMonitor monitor) throws NordicMappingException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(memoryPlan, "memoryPlan must not be null");
        Objects.requireNonNull(decoded, "decoded must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        monitor.checkCancelled();

        // 1. Language binding verification
        String actualLanguage = program.getLanguageID().getIdAsString();
        if (!actualLanguage.toUpperCase().startsWith("ARM:LE:32")) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_LANGUAGE_MISMATCH,
                String.format("Program language (%s) is not a 32-bit little-endian ARM processor language definition",
                    actualLanguage)
            );
        }

        int blocksCreated = 0;
        int registersApplied = 0;

        // Transactional mutation with clean rollback on failure
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Map Embedra Nordic firmware layout")) {

            Memory memory = program.getMemory();

            // 2. Map initialized firmware segments from decoded input
            for (DecodedSegment seg : decoded.segments()) {
                monitor.checkCancelled();
                if (findBlock(memory, seg.address()) == null) {
                    try {
                        Address segAddr = addr(program, seg.address());
                        boolean isWrite = (seg.address() == 0x10001000L)
                            || (seg.address() >= 0x20000000L && seg.address() < 0x30000000L);
                        boolean isExec = seg.address() < 0x20000000L;
                        MemoryBlock block = memory.createInitializedBlock(
                            seg.name(), segAddr, new ByteArrayInputStream(seg.data()),
                            seg.data().length, monitor, false
                        );
                        block.setRead(true);
                        block.setWrite(isWrite);
                        block.setExecute(isExec);
                        blocksCreated++;
                    } catch (Exception e) {
                        throw new NordicMappingException(
                            DiagnosticCode.NORDIC_MAPPING_FAILED,
                            "Failed to create initialized memory block " + seg.name() + " at 0x"
                                + Long.toHexString(seg.address()) + ": " + e.getMessage(), e);
                    }
                }
            }

            // 3. Map uninitialized target memory regions from plan
            for (NordicMemoryRegion region : memoryPlan.regions()) {
                monitor.checkCancelled();
                if (!overlaps(memory, region.startAddress(), region.sizeBytes())) {
                    createUninitializedBlock(
                        memory,
                        region.name(),
                        region.startAddress(),
                        region.sizeBytes(),
                        region.readable(),
                        region.writable(),
                        region.executable(),
                        region.startAddress() >= 0x40000000L
                    );
                    blocksCreated++;
                }
            }

            monitor.checkCancelled();

            // 4. Apply entry points and vector labels
            if (decoded.entryPoint() > 0) {
                Address entryAddr = addr(program, decoded.entryPoint());
                if (decoded.relocatedAppOffset().isPresent()) {
                    createLabelSafe(program, entryAddr, "Application_Reset_Handler", true);
                    createLabelSafe(program, entryAddr, "Reset_Handler", false);
                } else {
                    createLabelSafe(program, entryAddr, "Reset_Handler", true);
                }
                program.getSymbolTable().addExternalEntryPoint(entryAddr);
            }

            // Label MBR and SoftDevice reset handlers if distinct from main entry
            for (DecodedSegment seg : decoded.segments()) {
                if (seg.address() == 0x00000000L && seg.data().length >= 8) {
                    ByteBuffer bb = ByteBuffer.wrap(seg.data()).order(ByteOrder.LITTLE_ENDIAN);
                    long mbrReset = (bb.getInt(4) & 0xFFFFFFFFL) & ~1L;
                    if (mbrReset > 0 && mbrReset != decoded.entryPoint()) {
                        createLabelSafe(program, addr(program, mbrReset), "MBR_Reset_Handler", false);
                    }
                } else if (seg.address() == 0x00001000L && seg.data().length >= 8) {
                    ByteBuffer bb = ByteBuffer.wrap(seg.data()).order(ByteOrder.LITTLE_ENDIAN);
                    long sdReset = (bb.getInt(4) & 0xFFFFFFFFL) & ~1L;
                    if (sdReset > 0 && sdReset != decoded.entryPoint()) {
                        createLabelSafe(program, addr(program, sdReset), "SoftDevice_Reset_Handler", false);
                    }
                }
            }

            // Label Bootloader reset handler if discovered in UICR
            if (decoded.bootloaderAddress().isPresent()) {
                long blAddr = decoded.bootloaderAddress().get();
                Address blAddress = addr(program, blAddr);
                createLabelSafe(program, blAddress, "Bootloader_Reset_Handler", true);
                program.getSymbolTable().addExternalEntryPoint(blAddress);
            }

            monitor.checkCancelled();

            // 5. Apply peripheral register definitions and comments
            if (peripheralPack != null) {
                for (NordicPeripheral periph : peripheralPack.peripherals()) {
                    Address periphBase = addr(program, periph.baseAddress());
                    try {
                        program.getListing().setComment(
                            periphBase, CommentType.PLATE,
                            NordicPeripheralSchemaTransform.formatPeripheralPlateComment(periph)
                        );
                    } catch (Exception ignored) {
                    }

                    for (NordicRegister reg : periph.registers()) {
                        Address regAddr = addr(program, reg.address());
                        try {
                            if (program.getSymbolTable().getPrimarySymbol(regAddr) == null) {
                                program.getSymbolTable().createLabel(regAddr, reg.name(), SourceType.IMPORTED);
                                registersApplied++;
                            }
                            program.getListing().setComment(
                                regAddr, CommentType.EOL,
                                NordicPeripheralSchemaTransform.formatRegisterComment(reg)
                            );
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            // 6. Record options & provenance
            var options = program.getOptions(OPTIONS_CATEGORY);
            options.setString("Exact Part", part.exactPart());
            options.setString("Series", part.series());
            options.setString("Input Format", decoded.format());
            options.setLong("Flash Base", part.flashStart());
            options.setLong("Flash Bytes", part.flashBytes());
            options.setLong("RAM Bytes", part.ramBytes());
            options.setLong("Entry Point", decoded.entryPoint());
            if (decoded.relocatedAppOffset().isPresent()) {
                options.setLong("Application Offset", decoded.relocatedAppOffset().get());
            }
            if (decoded.bootloaderAddress().isPresent()) {
                options.setLong("Bootloader Address", decoded.bootloaderAddress().get());
            }

            transaction.commit();
        }

        return new NordicImportReport(
            part.exactPart(),
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
            "Successfully mapped Nordic nRF firmware layout into Ghidra"
        );
    }

    private static Address addr(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static MemoryBlock findBlock(Memory memory, long address) {
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getStart().getOffset() == address) {
                return block;
            }
        }
        return null;
    }

    private static boolean overlaps(Memory memory, long start, long size) {
        Address startAddr = memory.getProgram().getAddressFactory().getDefaultAddressSpace().getAddress(start);
        Address endAddr = memory.getProgram()
            .getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(start + size - 1L);
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getStart().compareTo(endAddr) <= 0 && block.getEnd().compareTo(startAddr) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static void createLabelSafe(Program program, Address addr, String name, boolean makePrimary) {
        try {
            ghidra.program.model.symbol.Symbol s =
                program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
            if (makePrimary && s != null) {
                s.setPrimary();
            }
        } catch (Exception ignored) {
        }
    }

    private static void createUninitializedBlock(
            Memory memory, String name, long start, long size,
            boolean r, boolean w, boolean x, boolean isVolatile) throws NordicMappingException {
        try {
            Address address = memory.getProgram().getAddressFactory().getDefaultAddressSpace().getAddress(start);
            MemoryBlock block = memory.createUninitializedBlock(name, address, size, false);
            block.setRead(r);
            block.setWrite(w);
            block.setExecute(x);
            block.setVolatile(isVolatile);
        } catch (Exception e) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_MAPPING_FAILED,
                String.format("Failed to create memory block %s (0x%08X, %d bytes): %s",
                    name, start, size, e.getMessage()), e);
        }
    }
}
