package io.github.rezabakhshi.embedra.ghidra.nordic;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Ghidra loader entry point for Nordic Semiconductor nRF firmware images (raw BIN, Intel HEX, ELF).
 */
public final class NordicFirmwareLoader extends AbstractLibrarySupportLoader {

    public static final String TARGET_PART_OPTION = "Target Silicon Part (optional override)";

    private final NordicFirmwareImportService importService;

    public NordicFirmwareLoader() {
        this(new NordicFirmwareImportService());
    }

    public NordicFirmwareLoader(NordicFirmwareImportService importService) {
        this.importService = Objects.requireNonNull(importService, "importService must not be null");
    }

    @Override
    public String getName() {
        return "Embedra Nordic nRF Firmware";
    }

    @Override
    public List<Option> getDefaultOptions(
            ByteProvider provider,
            LoadSpec loadSpec,
            DomainObject domainObject,
            boolean loadIntoProgram,
            boolean mirrorFsLayout) {
        List<Option> options = new ArrayList<>(
                super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout));
        options.add(new Option(TARGET_PART_OPTION, String.class, "",
                "Embedra Nordic target", "Explicitly override target silicon part (e.g. nRF52840-QIAA, nRF5340-QKAA)"));
        return options;
    }

    @Override
    public String validateOptions(
            ByteProvider provider,
            LoadSpec loadSpec,
            List<Option> options,
            Program program) {
        String inherited = super.validateOptions(provider, loadSpec, options, program);
        if (inherited != null) {
            return inherited;
        }

        for (Option opt : options) {
            if (TARGET_PART_OPTION.equals(opt.getName())) {
                String val = (String) opt.getValue();
                if (val != null && !val.isBlank()
                        && importService.catalogRegistry().findExactPart(val.trim()).isEmpty()) {
                    return "Unknown Nordic silicon part: " + val;
                }
            }
        }
        return null;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        byte[] input = readBounded(provider);

        try {
            NordicInputDecoder.DecodedNordicFirmware decoded =
                NordicInputDecoder.decode(input, ParserLimits.defaults());
            if (!decoded.segments().isEmpty()) {
                LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default");
                return List.of(new LoadSpec(this, 0, pair, true));
            }
        } catch (NordicMappingException | RuntimeException ignored) {
            // Not a supported or valid Nordic image
        }

        return List.of();
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] input = readBounded(settings.provider());
        String targetPart = findStringOption(settings.options(), TARGET_PART_OPTION);

        NordicImportReport report = importService.importFirmware(
            program,
            input,
            targetPart,
            ParserLimits.defaults(),
            settings.monitor()
        );

        settings.log().appendMsg(getName(), "Mapped " + report.blocksCreated()
            + " memory blocks and " + report.registersApplied() + " registers for "
            + report.exactPart() + " (" + report.series() + ") into " + report.languageId());
    }

    private static String findStringOption(List<Option> options, String name) {
        if (options == null) {
            return "";
        }
        for (Option opt : options) {
            if (name.equals(opt.getName()) && opt.getValue() instanceof String s) {
                return s.trim();
            }
        }
        return "";
    }

    private static byte[] readBounded(ByteProvider provider) throws IOException {
        long length = provider.length();
        if (length > ParserLimits.defaults().maxInputBytes() || length > Integer.MAX_VALUE) {
            throw new IOException("Nordic firmware image exceeds configured input-byte limit");
        }
        return provider.readBytes(0, length);
    }
}
