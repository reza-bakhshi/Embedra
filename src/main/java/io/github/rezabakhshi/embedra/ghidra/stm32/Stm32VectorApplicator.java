package io.github.rezabakhshi.embedra.ghidra.stm32;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32VectorDiscovery;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.io.IOException;
import java.util.Objects;

/** Creates primitive vector words only after a caller confirms a discovered table. */
public final class Stm32VectorApplicator {
    public static final String PROVENANCE_OPTIONS = "Embedra STM32 Vector Confirmation";

    private Stm32VectorApplicator() {
    }

    public static void apply(Program program, Stm32VectorDiscovery.Confirmed confirmed,
            TaskMonitor monitor) throws IOException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(confirmed, "confirmed");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        if (!program.getLanguageID().getIdAsString().startsWith("ARM:LE:32:")) {
            throw new IOException("Vector confirmation requires a selected little-endian ARM program");
        }
        var candidate = confirmed.candidate();
        Address base;
        try {
            base = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(candidate.tableAddress());
            var options = program.getOptions(PROVENANCE_OPTIONS);
            long existing = options.getLong("Confirmed Vector Address", -1);
            if (existing != -1 && existing != candidate.tableAddress()) {
                throw new IOException("Program already records another confirmed vector table");
            }
            for (int index = 0; index < candidate.words().size(); index++) {
                monitor.checkCancelled();
                Address address = base.addNoWrap(index * 4L);
                long mapped = Integer.toUnsignedLong(program.getMemory().getInt(address));
                if (mapped != candidate.words().get(index)) {
                    throw new IOException("Mapped vector bytes differ from the confirmed candidate");
                }
                if (program.getListing().getInstructionContaining(address) != null) {
                    throw new IOException("Existing instruction conflicts with confirmed vector");
                }
                var data = program.getListing().getDefinedDataContaining(address);
                if (data != null && (data.getMinAddress().compareTo(address) != 0
                        || !data.getDataType().isEquivalent(DWordDataType.dataType))) {
                    throw new IOException("Existing data conflicts with confirmed vector");
                }
            }
            try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                    program, "Apply confirmed STM32 vector table")) {
                for (int index = 0; index < candidate.words().size(); index++) {
                    monitor.checkCancelled();
                    Address address = base.addNoWrap(index * 4L);
                    if (program.getListing().getDefinedDataAt(address) == null) {
                        program.getListing().createData(address, DWordDataType.dataType);
                    }
                }
                options.setLong("Confirmed Vector Address", candidate.tableAddress());
                options.setString("Selection", "USER_CONFIRMED");
                options.setString("Input SHA-256", candidate.inputSha256());
                transaction.commit();
            }
        }
        catch (CancelledException | IOException exception) {
            throw exception;
        }
        catch (Exception exception) {
            throw new IOException("Could not apply confirmed vector table", exception);
        }
    }
}
