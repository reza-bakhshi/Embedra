package io.github.rezabakhshi.embedra.ghidra.rp;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.rp.Rp2040TargetProvider;
import io.github.rezabakhshi.embedra.targets.rp.Rp2350TargetProvider;
import io.github.rezabakhshi.embedra.targets.rp.RpTargetProvider;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2040BootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350Architecture;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350BootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.Rp2040VectorTable;
import io.github.rezabakhshi.embedra.targets.rp.Rp2350VectorTable;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Transactional mapper of validated Raspberry Pi segments and boot metadata into a Ghidra program.
 */
public final class RpFirmwareMapper {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra RP Firmware";

    public RpImportReport map(
            Program program,
            List<RpUf2Segment> segments,
            RpTargetProvider provider,
            RpBootMetadata bootMetadata,
            String containerFormat,
            TaskMonitor monitor) throws RpMappingException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(segments, "segments must not be null");
        Objects.requireNonNull(provider, "provider must not be null");
        Objects.requireNonNull(bootMetadata, "bootMetadata must not be null");
        Objects.requireNonNull(containerFormat, "containerFormat must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        monitor.checkCancelled();

        String bootArch = "ARM";
        if (bootMetadata instanceof Rp2350BootMetadata b2350
                && b2350.architecture() == Rp2350Architecture.RISCV) {
            bootArch = Rp2350TargetProvider.ARCH_RISCV;
        }
        LanguageSelection language = provider.selectLanguage(bootArch);
        validateProgramLanguage(program, language);

        // Check for memory overlap conflicts before starting transaction
        for (RpUf2Segment segment : segments) {
            Address start = address(program, segment.targetAddress());
            Address end = address(program, segment.endAddress() - 1);
            for (MemoryBlock existing : program.getMemory().getBlocks()) {
                if (overlaps(start, end, existing)) {
                    throw new RpMappingException(DiagnosticCode.RP_MAPPING_CONFLICT,
                            "Existing memory block " + existing.getName() + " conflicts with RP segment at 0x"
                                    + Long.toHexString(segment.targetAddress()));
                }
            }
        }

        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Map validated Raspberry Pi firmware")) {

            // Create memory blocks
            for (RpUf2Segment segment : segments) {
                monitor.checkCancelled();
                Address start = address(program, segment.targetAddress());
                String blockName = "rp_flash_" + Long.toHexString(segment.targetAddress());
                MemoryBlock block = program.getMemory().createInitializedBlock(
                        blockName,
                        start,
                        new ByteArrayInputStream(segment.data()),
                        segment.length(),
                        monitor,
                        false);
                block.setRead(true);
                block.setWrite(false);
                block.setExecute(true);
            }

            monitor.checkCancelled();

            // Entry point and label
            long entryPoint = bootMetadata.entryPoint();
            if (entryPoint != 0) {
                Address entryAddress = address(program, entryPoint);
                Symbol existing = program.getSymbolTable().getPrimarySymbol(entryAddress);
                if (existing == null) {
                    program.getSymbolTable().createLabel(entryAddress, "entry", SourceType.IMPORTED);
                }
                program.getSymbolTable().addExternalEntryPoint(entryAddress);
            }

            // Bookmarks
            Address baseAddr = address(program, bootMetadata.flashBaseAddress());
            String bootDesc = bootMetadata.series() + " boot stage: "
                    + (bootMetadata instanceof Rp2040BootMetadata ? "boot2 preamble" : "IMAGE_DEF header");
            program.getBookmarkManager().setBookmark(baseAddr, BookmarkType.INFO, "Embedra RP Boot", bootDesc);

            if (bootMetadata instanceof Rp2040BootMetadata rp2040Meta && rp2040Meta.isVectorTableValid()) {
                Address vtAddr = address(program, 0x10000100L);
                program.getBookmarkManager().setBookmark(
                        vtAddr, BookmarkType.INFO, "Embedra RP Vector Table",
                        "RP2040 Vector Table (Initial SP: 0x" + Long.toHexString(rp2040Meta.initialSp()) + ")");
                applyRp2040VectorLabels(program, 0x10000100L);
            } else if (bootMetadata instanceof Rp2350BootMetadata rp2350Meta
                    && rp2350Meta.vectorTableAddress().isPresent()) {
                long vt = rp2350Meta.vectorTableAddress().getAsLong();
                Address vtAddr = address(program, vt);
                program.getBookmarkManager().setBookmark(
                        vtAddr, BookmarkType.INFO, "Embedra RP Vector Table", "RP2350 Vector Table");
                applyRp2350VectorLabels(program, vt, rp2350Meta.architecture() == Rp2350Architecture.RISCV);
            }

            if (entryPoint != 0) {
                Address entryAddress = address(program, entryPoint);
                program.getBookmarkManager().setBookmark(
                        entryAddress, BookmarkType.INFO, "Embedra RP Entry", "Reset execution entry point");
            }

            // Program Options
            var options = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            options.setString("Target Silicon Part", provider.siliconRecord().exactPart());
            options.setString("Container Format", containerFormat);
            options.setString("Provider ID", provider.providerId());
            if (provider instanceof Rp2040TargetProvider) {
                options.setString("PIO Blocks", "PIO0, PIO1");
                options.setInt("PIO State Machines", 8);
            } else if (provider instanceof Rp2350TargetProvider rp2350Prov) {
                options.setString("PIO Blocks", "PIO0, PIO1, PIO2");
                options.setInt("PIO State Machines", 12);
                options.setInt("GPIO Count", rp2350Prov.gpioCount());
            }
            for (Map.Entry<String, Object> entry : bootMetadata.metadataProperties().entrySet()) {
                Object val = entry.getValue();
                if (val instanceof String s) {
                    options.setString(entry.getKey(), s);
                } else if (val instanceof Boolean b) {
                    options.setBoolean(entry.getKey(), b);
                } else if (val instanceof Long l) {
                    options.setLong(entry.getKey(), l);
                } else if (val instanceof Integer i) {
                    options.setInt(entry.getKey(), i);
                }
            }

            transaction.commit();
        } catch (LockException | MemoryConflictException | AddressOverflowException
                | InvalidInputException exception) {
            throw new RpMappingException(DiagnosticCode.RP_MAPPING_FAILED,
                    "Ghidra rejected the Raspberry Pi firmware mapping: " + exception.getMessage(), exception);
        }

        return new RpImportReport(
                bootMetadata.series(),
                provider.siliconRecord().exactPart(),
                containerFormat,
                program.getLanguageID().getIdAsString(),
                program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
                segments.size(),
                bootMetadata.entryPoint(),
                bootMetadata);
    }

    private static void validateProgramLanguage(Program program, LanguageSelection language)
            throws RpMappingException {
        String actualLanguage = program.getLanguageID().getIdAsString();
        boolean isArm = actualLanguage.startsWith("ARM:LE:32:");
        boolean isRiscv = actualLanguage.startsWith("RISCV:LE:32:");

        boolean expectedRiscv = language.languageId().startsWith("RISCV");
        if (expectedRiscv && !isRiscv) {
            throw new RpMappingException(DiagnosticCode.RP_LANGUAGE_MISMATCH,
                    "Program language (" + actualLanguage + ") is not RISC-V 32-bit LE");
        }
        if (!expectedRiscv && !isArm) {
            throw new RpMappingException(DiagnosticCode.RP_LANGUAGE_MISMATCH,
                    "Program language (" + actualLanguage + ") is not ARM 32-bit LE");
        }
    }

    private static boolean overlaps(Address start, Address end, MemoryBlock existing) {
        return start.getAddressSpace().equals(existing.getStart().getAddressSpace())
                && start.compareTo(existing.getEnd()) <= 0
                && existing.getStart().compareTo(end) <= 0;
    }

    private static Address address(Program program, long offset) throws RpMappingException {
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (RuntimeException exception) {
            throw new RpMappingException(DiagnosticCode.RP_MAPPING_FAILED,
                    "Address 0x" + Long.toHexString(offset) + " is outside program address space", exception);
        }
    }

    private static void applyRp2040VectorLabels(Program program, long vtBase) {
        try {
            Address vtAddr = address(program, vtBase);
            if (program.getSymbolTable().getPrimarySymbol(vtAddr) == null) {
                program.getSymbolTable().createLabel(vtAddr, "vector_table", SourceType.IMPORTED);
            }
            byte[] buf = new byte[4];
            for (Map.Entry<Integer, String> entry : Rp2040VectorTable.allVectors().entrySet()) {
                int index = entry.getKey();
                if (index == 0) {
                    continue; // initial SP
                }
                long vecAddr = vtBase + (index * 4L);
                Address addr = address(program, vecAddr);
                if (program.getMemory().contains(addr) && program.getMemory().getBytes(addr, buf) == 4) {
                    long target = Integer.toUnsignedLong(ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN).getInt());
                    long targetAligned = target & ~1L;
                    if (targetAligned >= 0x10000000L && targetAligned < 0x20042000L) {
                        Address targetAddress = address(program, targetAligned);
                        if (program.getMemory().contains(targetAddress)
                                && program.getSymbolTable().getPrimarySymbol(targetAddress) == null) {
                            program.getSymbolTable().createLabel(targetAddress, entry.getValue(), SourceType.IMPORTED);
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // Non-fatal labeling failure
        }
    }

    private static void applyRp2350VectorLabels(Program program, long vtBase, boolean isRiscV) {
        try {
            Address vtAddr = address(program, vtBase);
            if (program.getSymbolTable().getPrimarySymbol(vtAddr) == null) {
                program.getSymbolTable().createLabel(vtAddr, "vector_table", SourceType.IMPORTED);
            }
            byte[] buf = new byte[4];
            if (!isRiscV) {
                for (Map.Entry<Integer, String> entry : Rp2350VectorTable.armAllVectors().entrySet()) {
                    int index = entry.getKey();
                    if (index == 0) {
                        continue;
                    }
                    long vecAddr = vtBase + (index * 4L);
                    Address addr = address(program, vecAddr);
                    if (program.getMemory().contains(addr) && program.getMemory().getBytes(addr, buf) == 4) {
                        long target = Integer.toUnsignedLong(
                                ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN).getInt());
                        long targetAligned = target & ~1L;
                        if (targetAligned >= 0x10000000L && targetAligned < 0x20082000L) {
                            Address targetAddress = address(program, targetAligned);
                            if (program.getMemory().contains(targetAddress)
                                    && program.getSymbolTable().getPrimarySymbol(targetAddress) == null) {
                                program.getSymbolTable().createLabel(
                                        targetAddress, entry.getValue(), SourceType.IMPORTED);
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // Non-fatal labeling failure
        }
    }
}

