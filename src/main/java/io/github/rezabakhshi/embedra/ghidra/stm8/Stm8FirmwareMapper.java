package io.github.rezabakhshi.embedra.ghidra.stm8;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryPlan;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8Peripheral;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8PeripheralPack;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8PeripheralSchemaTransform;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8Register;
import io.github.rezabakhshi.embedra.targets.stm8.vector.Stm8VectorEntry;
import io.github.rezabakhshi.embedra.targets.stm8.vector.Stm8VectorTable;
import java.io.ByteArrayInputStream;
import java.util.Objects;

/**
 * Maps pure STM8 memory layouts, vector tables, and peripheral packs into Ghidra programs (STM8-008).
 */
public final class Stm8FirmwareMapper {

    public static final String OPTIONS_CATEGORY = "Embedra STM8 Firmware";

    public Stm8ImportReport map(
            Program program,
            Stm8PartRecord part,
            Stm8MemoryPlan memoryPlan,
            Stm8VectorTable vectorTable,
            Stm8PeripheralPack peripheralPack,
            byte[] flashBytes,
            String inputFormat,
            TaskMonitor monitor) throws Stm8MappingException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(memoryPlan, "memoryPlan must not be null");
        Objects.requireNonNull(inputFormat, "inputFormat must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        monitor.checkCancelled();

        // 1. Language binding verification per STM8-006
        String actualLanguage = program.getLanguageID().getIdAsString();
        if (!actualLanguage.toUpperCase().startsWith("STM8")) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_LANGUAGE_MISMATCH,
                String.format("Program language (%s) is not an 8-bit STM8 processor language definition",
                    actualLanguage)
            );
        }

        int blocksCreated = 0;
        int vectorsApplied = 0;
        int registersApplied = 0;

        // Transactional mutation with clean rollback on failure
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Map Embedra STM8 firmware layout")) {

            Memory memory = program.getMemory();

            // 2. Map memory blocks
            // RAM (0x000000)
            if (findBlock(memory, 0x000000L) == null) {
                createUninitializedBlock(memory, "RAM", 0x000000L, part.ramBytes(), true, true, false, false);
                blocksCreated++;
            }

            // Data EEPROM (0x004000)
            if (part.eepromBytes() > 0 && findBlock(memory, 0x004000L) == null) {
                createUninitializedBlock(
                    memory, "DATA_EEPROM", 0x004000L, part.eepromBytes(), true, true, false, false);
                blocksCreated++;
            }

            // Option Bytes (0x004800)
            if (part.optionBytes() > 0 && findBlock(memory, 0x004800L) == null) {
                createUninitializedBlock(
                    memory, "OPTION_BYTES", 0x004800L, part.optionBytes(), true, true, false, true);
                blocksCreated++;
            }

            // Peripherals (0x005000)
            if (findBlock(memory, 0x005000L) == null) {
                createUninitializedBlock(memory, "PERIPHERALS", 0x005000L, 2048L, true, true, false, true);
                blocksCreated++;
            }

            // Boot ROM (0x006000)
            if (part.bootRomBytes() > 0 && findBlock(memory, 0x006000L) == null) {
                createUninitializedBlock(memory, "BOOT_ROM", 0x006000L, part.bootRomBytes(), true, false, true, false);
                blocksCreated++;
            }

            // Program Flash (0x008000)
            MemoryBlock flashBlock = findBlock(memory, 0x008000L);
            if (flashBlock == null) {
                if (flashBytes != null && flashBytes.length > 0) {
                    try {
                        Address flashAddr = addr(program, 0x008000L);
                        memory.createInitializedBlock(
                            "FLASH", flashAddr, new ByteArrayInputStream(flashBytes),
                            flashBytes.length, monitor, false
                        );
                        blocksCreated++;
                    } catch (Exception e) {
                        throw new Stm8MappingException(
                            DiagnosticCode.STM8_MAPPING_FAILED,
                            "Failed to create initialized FLASH memory block: " + e.getMessage(), e);
                    }
                } else {
                    createUninitializedBlock(memory, "FLASH", 0x008000L, part.flashBytes(), true, false, true, false);
                    blocksCreated++;
                }
            }

            monitor.checkCancelled();

            // 3. Apply vector table entries and entry points
            if (vectorTable != null) {
                // Set primary entry point at Reset vector target
                long resetTarget = vectorTable.resetTargetAddress();
                if (resetTarget > 0) {
                    Address entryAddr = addr(program, resetTarget);
                    program.getSymbolTable().addExternalEntryPoint(entryAddr);
                    try {
                        program.getSymbolTable().createLabel(entryAddr, "Reset_Handler", SourceType.IMPORTED);
                    } catch (Exception ignored) {
                        // Label might already exist
                    }
                }

                // Label vector table slots and ISR targets
                for (Stm8VectorEntry entry : vectorTable.entries()) {
                    Address slotAddr = addr(program, entry.vectorAddress());
                    try {
                        program.getListing().setComment(
                            slotAddr, CommentType.EOL,
                            String.format("Vector Slot %d: %s -> 0x%06X (%s)",
                                entry.slot().slotIndex(), entry.slot().canonicalName(),
                                entry.targetAddress(), entry.handlerLabel())
                        );
                    } catch (Exception ignored) {
                    }

                    if (entry.isValid() && entry.targetAddress() > 0 && entry.slot().slotIndex() != 0) {
                        Address targetAddr = addr(program, entry.targetAddress());
                        try {
                            if (program.getSymbolTable().getPrimarySymbol(targetAddr) == null) {
                                program.getSymbolTable().createLabel(
                                    targetAddr, entry.handlerLabel(), SourceType.IMPORTED);
                                vectorsApplied++;
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            monitor.checkCancelled();

            // 4. Apply peripheral register definitions and comments
            if (peripheralPack != null) {
                for (Stm8Peripheral periph : peripheralPack.peripherals()) {
                    Address periphBase = addr(program, periph.baseAddress());
                    try {
                        program.getListing().setComment(
                            periphBase, CommentType.PLATE,
                            Stm8PeripheralSchemaTransform.formatPeripheralPlateComment(periph)
                        );
                    } catch (Exception ignored) {
                    }

                    for (Stm8Register reg : periph.registers()) {
                        Address regAddr = addr(program, reg.address());
                        try {
                            if (program.getSymbolTable().getPrimarySymbol(regAddr) == null) {
                                program.getSymbolTable().createLabel(regAddr, reg.name(), SourceType.IMPORTED);
                                registersApplied++;
                            }
                            program.getListing().setComment(
                                regAddr, CommentType.EOL,
                                Stm8PeripheralSchemaTransform.formatRegisterComment(reg)
                            );
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            // 5. Record options & provenance
            var options = program.getOptions(OPTIONS_CATEGORY);
            options.setString("Exact Part", part.exactPart());
            options.setString("Family", part.family());
            options.setString("Input Format", inputFormat);
            options.setLong("Flash Base", 0x008000L);
            options.setLong("Flash Bytes", part.flashBytes());
            options.setLong("RAM Bytes", part.ramBytes());
            options.setLong("EEPROM Bytes", part.eepromBytes());

            transaction.commit();
        }

        return new Stm8ImportReport(
            part.exactPart(),
            part.family(),
            inputFormat,
            program.getLanguageID().getIdAsString(),
            program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
            vectorTable != null ? vectorTable.resetTargetAddress() : 0x008000L,
            0x008000L,
            part.flashBytes(),
            blocksCreated,
            vectorsApplied,
            registersApplied,
            true,
            "Successfully mapped STM8 firmware layout into Ghidra"
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

    private static void createUninitializedBlock(
            Memory memory, String name, long start, long size,
            boolean r, boolean w, boolean x, boolean isVolatile) throws Stm8MappingException {
        try {
            Address address = memory.getProgram().getAddressFactory().getDefaultAddressSpace().getAddress(start);
            MemoryBlock block = memory.createUninitializedBlock(name, address, size, false);
            block.setRead(r);
            block.setWrite(w);
            block.setExecute(x);
            block.setVolatile(isVolatile);
        } catch (Exception e) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_MAPPING_FAILED,
                String.format("Failed to create memory block %s (0x%06X, %d bytes): %s",
                    name, start, size, e.getMessage()), e);
        }
    }
}
