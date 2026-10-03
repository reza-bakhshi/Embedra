package io.github.rezabakhshi.embedra.ghidra.rp.pio;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.rp.RpPioBlock;
import io.github.rezabakhshi.embedra.targets.rp.RpTargetProvider;
import io.github.rezabakhshi.embedra.targets.rp.pio.RpPioInstruction;
import io.github.rezabakhshi.embedra.targets.rp.pio.RpPioProgram;
import java.util.List;
import java.util.Objects;

/**
 * Ghidra applicator for discovered Raspberry Pi PIO programs and hardware block apertures.
 * <p>
 * Ensures PIO programs are annotated with bookmarks, plate/EOL disassembly comments,
 * and 16-bit word data units, strictly avoiding ARM Thumb or RISC-V disassembly.
 */
public final class RpPioApplicator {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra RP PIO";

    public static final String BOOKMARK_CATEGORY_PROGRAM = "Embedra RP PIO";

    public static final String BOOKMARK_CATEGORY_APERTURE = "Embedra RP PIO Aperture";

    private RpPioApplicator() {
    }

    /**
     * Applies discovered PIO programs and hardware block apertures to a Ghidra program.
     */
    public static void apply(
            Program program,
            List<RpPioProgram> programs,
            RpTargetProvider provider,
            TaskMonitor monitor) {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(programs, "programs must not be null");
        Objects.requireNonNull(provider, "provider must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Annotate Raspberry Pi PIO Programs")) {

            // 1. Annotate each discovered PIO program
            for (RpPioProgram pioProg : programs) {
                monitor.checkCancelled();
                annotateProgram(program, pioProg);
            }

            // 2. Register PIO hardware block apertures
            for (RpPioBlock block : provider.pioBlocks()) {
                monitor.checkCancelled();
                registerBlockAperture(program, block, monitor);
            }

            // 3. Program options
            var options = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            options.setInt("Discovered Programs Count", programs.size());
            options.setInt("PIO Blocks Available", provider.pioBlocks().size());
            options.setInt("State Machines Available", provider.pioBlocks().size() * 4);

            tx.commit();
        } catch (Exception e) {
            // Log or propagate as needed
        }
    }

    private static void annotateProgram(Program program, RpPioProgram prog) {
        try {
            Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(prog.address());
            Address end = program.getAddressFactory().getDefaultAddressSpace().getAddress(prog.endAddress() - 1);

            // Safety guard: if there is an existing CPU function or instruction at start,
            // and this PIO program was discovered without a struct anchor, do NOT overwrite CPU code.
            if (prog.structureAddress().isEmpty()) {
                if (program.getListing().getInstructionAt(start) != null
                        || program.getListing().getFunctionAt(start) != null) {
                    return;
                }
            }

            // Clear any erroneous CPU code units (ARM Thumb / RISC-V) across PIO program range
            program.getListing().clearCodeUnits(start, end, false);

            // Label program start if unlabelled
            Symbol existing = program.getSymbolTable().getPrimarySymbol(start);
            if (existing == null) {
                program.getSymbolTable().createLabel(start, prog.name(), SourceType.IMPORTED);
            }

            // Set Plate Comment at program start
            StringBuilder plate = new StringBuilder();
            plate.append("=== Embedra Disassembled PIO Program ===\n");
            plate.append("Program: ").append(prog.name()).append('\n');
            plate.append("Length: ").append(prog.length()).append(" instructions\n");
            plate.append("Origin: ").append(prog.isRelocatable() ? "relocatable (-1)" : prog.origin()).append('\n');
            plate.append("Wrap target: ").append(prog.config().wrapTarget())
                    .append(prog.config().isWrapExplicit() ? "" : " (uncertain)").append('\n');
            plate.append("Wrap: ").append(prog.config().wrap())
                    .append(prog.config().isWrapExplicit() ? "" : " (uncertain)").append('\n');
            plate.append("Side-set: ")
                    .append(prog.config().isSideSetKnown()
                            ? prog.config().sideSetCount() + " bits"
                            : "unconfigured (uncertain)")
                    .append('\n');
            plate.append("\nDisassembly:\n");

            for (int i = 0; i < prog.instructions().size(); i++) {
                RpPioInstruction instr = prog.instructions().get(i);
                plate.append(String.format("  %02d: %s\n", i, instr.toAssemblyString()));
            }
            plate.append("========================================");
            program.getListing().setComment(start, CommentType.PLATE, plate.toString());

            // Set bookmark at program start
            program.getBookmarkManager().setBookmark(
                    start,
                    BookmarkType.INFO,
                    BOOKMARK_CATEGORY_PROGRAM,
                    String.format("PIO Program (%d instructions, origin=%s)",
                            prog.length(), prog.isRelocatable() ? "relocatable" : String.valueOf(prog.origin())));

            // Set 16-bit word data type and EOL comment for each instruction
            for (int i = 0; i < prog.instructions().size(); i++) {
                Address instrAddr = start.add(i * 2L);
                RpPioInstruction instr = prog.instructions().get(i);

                try {
                    program.getListing().createData(instrAddr, WordDataType.dataType);
                } catch (Exception ignored) {
                    // Retain existing data definition if conflict occurs
                }

                program.getListing().setComment(instrAddr, CommentType.EOL, "[PIO] " + instr.toAssemblyString());
            }
        } catch (Exception ignored) {
            // Continue with other programs
        }
    }

    private static void registerBlockAperture(Program program, RpPioBlock block, TaskMonitor monitor) {
        try {
            Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(block.baseAddress());

            if (!program.getMemory().contains(base)) {
                String blockName = block.blockName().toLowerCase();
                MemoryBlock memBlock = program.getMemory().createUninitializedBlock(
                        blockName, base, 0x1000L, false);
                memBlock.setRead(true);
                memBlock.setWrite(true);
                memBlock.setExecute(false);
                memBlock.setVolatile(true);
            }

            Symbol existing = program.getSymbolTable().getPrimarySymbol(base);
            if (existing == null) {
                program.getSymbolTable().createLabel(base, block.blockName().toLowerCase(), SourceType.IMPORTED);
            }

            program.getBookmarkManager().setBookmark(
                    base,
                    BookmarkType.INFO,
                    BOOKMARK_CATEGORY_APERTURE,
                    String.format("PIO Block %d (%d State Machines, %d Words Instr Mem)",
                            block.blockIndex(), block.stateMachineCount(), block.instructionMemoryWords()));
        } catch (Exception ignored) {
            // Peripheral aperture conflict resolution
        }
    }
}
