package io.github.rezabakhshi.embedra.ghidra.stm32;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32RawBinPlan;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

/** Maps an explicitly planned raw BIN through Ghidra's native BinaryLoader. */
public final class Stm32RawBinImporter {
    public static final String PROVENANCE_OPTIONS = "Embedra STM32 Raw Import";

    private Stm32RawBinImporter() {
    }

    public static void importInto(Program program, ByteProvider provider,
            Stm32RawBinPlan plan, Stm32CuratedPartIds selection, TaskMonitor monitor)
            throws IOException, LoadException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        if (!selection.containsExactPart(plan.exactPart())) {
            throw new IOException("Raw BIN plan does not name an exact curated STM32 part");
        }
        if (provider.length() != plan.length()) {
            throw new IOException("Raw BIN bytes do not match the explicit import plan");
        }
        String languageId = program.getLanguageID().getIdAsString();
        if (!languageId.startsWith("ARM:LE:32:")) {
            throw new IOException("Raw STM32 import needs a selected 32-bit little-endian ARM program");
        }
        Address base = program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(plan.baseAddress());
        BinaryLoader loader = new BinaryLoader();
        LoadSpec spec = new LoadSpec(loader, 0,
            new LanguageCompilerSpecPair(program.getLanguageID(),
                program.getCompilerSpec().getCompilerSpecID()), false);
        List<Option> options = loader.getDefaultOptions(provider, spec, program, true, false);
        Option baseOption = options.stream()
            .filter(option -> BinaryLoader.OPTION_NAME_BASE_ADDR.equals(option.getName()))
            .findFirst().orElseThrow();
        baseOption.setValue(base);
        String validation = loader.validateOptions(provider, spec, options, program);
        if (validation != null) {
            throw new IOException("Raw BIN import options are invalid: " + validation);
        }
        ImporterSettings settings = new ImporterSettings(provider, provider.getName(), null,
            "/", false, spec, options, new Object(), new MessageLog(), monitor);
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Import explicitly based STM32 raw BIN")) {
            var provenance = program.getOptions(PROVENANCE_OPTIONS);
            String existingPart = provenance.getString("Exact Part", null);
            if (existingPart != null && !existingPart.equals(plan.exactPart())) {
                throw new IOException("Program already records a different exact STM32 part");
            }
            loader.loadInto(program, settings);
            monitor.checkCancelled();
            provenance.setString("Exact Part", plan.exactPart());
            provenance.setLong("Explicit Base", plan.baseAddress());
            provenance.setLong("Input Length", plan.length());
            provenance.setString("Base Selection", "EXPLICIT");
            transaction.commit();
        }
    }
}
