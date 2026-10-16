package io.github.rezabakhshi.embedra.ghidra.atmel;

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
 * Ghidra loader entry point for Atmel / Microchip firmware images (raw BIN, Intel HEX, ELF).
 */
public final class AtmelFirmwareLoader extends AbstractLibrarySupportLoader {

    public static final String TARGET_PART_OPTION = "Target Silicon Part (optional override)";

    private final AtmelFirmwareImportService importService;

    public AtmelFirmwareLoader() {
        this(new AtmelFirmwareImportService());
    }

    public AtmelFirmwareLoader(AtmelFirmwareImportService importService) {
        this.importService = Objects.requireNonNull(importService, "importService must not be null");
    }

    @Override
    public String getName() {
        return "Embedra Atmel / Microchip Firmware";
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
                "Embedra Atmel target",
                "Explicitly override target silicon part (e.g. ATmega328P, ATmega2560, SAMD21G18A, SAME70Q21)"));
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
                        && importService.catalogRegistry().findPart(val.trim()).isEmpty()) {
                    return "Unknown Atmel / Microchip silicon part: " + val;
                }
            }
        }
        return null;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        byte[] input = readBounded(provider);

        try {
            AtmelInputDecoder.DecodedAtmelFirmware decoded =
                AtmelInputDecoder.decode(input, ParserLimits.defaults());
            if (!decoded.segments().isEmpty()) {
                LanguageCompilerSpecPair pair;
                if (decoded.isAvr()) {
                    if (decoded.maxAddress() > 65536L) {
                        pair = new LanguageCompilerSpecPair("avr8:LE:16:atmega256", "gcc");
                    } else {
                        pair = new LanguageCompilerSpecPair("avr8:LE:16:default", "gcc");
                    }
                } else {
                    pair = new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default");
                }
                return List.of(new LoadSpec(this, 0, pair, true));
            }
        } catch (AtmelMappingException ignored) {
            // Not a supported or valid Atmel image
        }

        return List.of();
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] input = readBounded(settings.provider());
        String targetPart = findStringOption(settings.options(), TARGET_PART_OPTION);

        try {
            AtmelImportReport report = importService.importFirmware(
                program,
                input,
                targetPart,
                ParserLimits.defaults(),
                settings.monitor()
            );

            settings.log().appendMsg(getName(), "Mapped " + report.blocksCreated()
                + " memory blocks and " + report.registersApplied() + " registers for "
                + report.exactPart() + " (" + report.family() + ") into " + report.languageId());
        } catch (AtmelMappingException e) {
            throw new IOException("Failed to load Atmel firmware: " + e.getMessage(), e);
        }
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
            throw new IOException("Atmel firmware image exceeds configured input-byte limit");
        }
        return provider.readBytes(0, length);
    }
}
