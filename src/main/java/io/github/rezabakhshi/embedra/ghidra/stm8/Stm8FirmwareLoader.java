package io.github.rezabakhshi.embedra.ghidra.stm8;

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
 * Ghidra loader entry point for STMicroelectronics STM8 firmware images (raw BIN, Intel HEX, S-Record, ELF).
 */
public final class Stm8FirmwareLoader extends AbstractLibrarySupportLoader {

    public static final String TARGET_PART_OPTION = "Target Silicon Part (optional override)";

    private final Stm8FirmwareImportService importService;

    public Stm8FirmwareLoader() {
        this(new Stm8FirmwareImportService());
    }

    public Stm8FirmwareLoader(Stm8FirmwareImportService importService) {
        this.importService = Objects.requireNonNull(importService, "importService");
    }

    @Override
    public String getName() {
        return "Embedra STM8 Firmware";
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
                "Embedra STM8 target", "Explicitly override target silicon part (e.g. STM8S003F3P6, STM8L151C8T6)"));
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
                    return "Unknown STM8 silicon part: " + val;
                }
            }
        }
        return null;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        byte[] input = readBounded(provider);

        // Quick check for candidates:
        // 1. ELF
        // 2. Intel HEX
        // 3. Motorola S-Record
        // 4. Raw BIN with reset JPF opcode (0x82) at offset 0
        try {
            Stm8InputDecoder.DecodedFirmware decoded = Stm8InputDecoder.decode(input, ParserLimits.defaults());
            if (decoded.flashBytes().length > 0) {
                // STM8:default:16:default or STM8:default:24:default
                LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair("STM8:default:16:default", "default");
                return List.of(new LoadSpec(this, 0, pair, true));
            }
        } catch (Stm8MappingException ignored) {
            // Not a supported or valid STM8 image
        }

        return List.of();
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] input = readBounded(settings.provider());
        String targetPart = findStringOption(settings.options(), TARGET_PART_OPTION);

        Stm8ImportReport report = importService.importFirmware(
            program,
            input,
            targetPart,
            ParserLimits.defaults(),
            settings.monitor()
        );

        settings.log().appendMsg(getName(), "Mapped " + report.blocksCreated()
            + " memory blocks and " + report.registersApplied() + " registers for "
            + report.exactPart() + " (" + report.family() + ") into " + report.languageId());
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
            throw new IOException("STM8 firmware image exceeds configured input-byte limit");
        }
        return provider.readBytes(0, length);
    }
}
