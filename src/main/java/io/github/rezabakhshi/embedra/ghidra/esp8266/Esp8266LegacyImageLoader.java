package io.github.rezabakhshi.embedra.ghidra.esp8266;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266Image;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266ImageDetection;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266ImageDetector;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266ImageParser;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266ImageSegment;
import io.github.rezabakhshi.embedra.ghidra.esp.EspMappingException;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.esp8266.Esp8266LegacyTargetProvider;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/** Separate Ghidra loader for ESP8266 ROM and software-bootloader images. */
public final class Esp8266LegacyImageLoader extends AbstractLibrarySupportLoader {
    public static final String FLASH_BASE_OPTION =
        "ESP8266 version 2 image flash base (confirm from flash layout)";

    public static final long DEFAULT_FLASH_BASE = 0x1000;

    @Override
    public String getName() {
        return "Embedra ESP8266 Legacy Image";
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean loadIntoProgram,
            boolean mirrorFsLayout) {
        List<Option> options = new ArrayList<>(super.getDefaultOptions(provider, loadSpec,
            domainObject, loadIntoProgram, mirrorFsLayout));
        options.add(new Option(FLASH_BASE_OPTION, Long.class, DEFAULT_FLASH_BASE,
            "Embedra ESP8266 mapping",
            "Required for version 2 IROM mapping; the image does not encode its flash base"));
        return options;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
            List<Option> options, Program program) {
        String inherited = super.validateOptions(provider, loadSpec, options, program);
        if (inherited != null) {
            return inherited;
        }
        Option option = findFlashBase(options);
        if (option == null || !(option.getValue() instanceof Long value)) {
            return "ESP8266 flash base option must have a Long value";
        }
        if (value < 0 || value > 0x000f_fff0L || (value & 0xfff) != 0) {
            return "ESP8266 flash base must be 4 KiB aligned and within IROM";
        }
        return null;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
            throws IOException {
        byte[] input = readBounded(provider);
        if (Esp8266ImageDetector.detect(input) != Esp8266ImageDetection.MATCH) {
            return List.of();
        }
        try {
            Esp8266Image image = Esp8266ImageParser.parse(input, ParserLimits.defaults(),
                CancellationToken.none());
            Esp8266LegacyTargetProvider target = new Esp8266LegacyTargetProvider();
            boolean mappable = image.segments().stream().allMatch(segment ->
                isMappable(segment, target));
            if (!mappable || !target.validateEntry(image.header().entryPoint(), image)
                    .accepted()) {
                return List.of();
            }
            LanguageSelection language = target.language();
            return List.of(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair(language.languageId(),
                    language.compilerSpecId()), true));
        }
        catch (DiagnosticException | IllegalArgumentException exception) {
            return List.of();
        }
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] input = readBounded(settings.provider());
        try {
            Esp8266Image image = Esp8266ImageParser.parse(input, ParserLimits.defaults(),
                settings.monitor()::isCancelled);
            long flashBase = flashBase(settings.options());
            var report = new Esp8266LegacyImageMapper().map(program, image, flashBase,
                new Esp8266LegacyTargetProvider(), settings.monitor());
            settings.log().appendMsg(getName(), "Mapped " + report.segments().size()
                + " validated ESP8266 legacy segments; exact ESP8266EX/ESP8285 identity "
                + "is not encoded");
        }
        catch (DiagnosticException | EspMappingException exception) {
            throw new IOException(exception.getMessage(), exception);
        }
    }

    private static boolean isMappable(Esp8266ImageSegment segment,
            Esp8266LegacyTargetProvider target) {
        try {
            long address = segment.resolveLoadAddress(DEFAULT_FLASH_BASE);
            return target.classify(new io.github.rezabakhshi.embedra.core.io.AddressRange(
                "default", address, segment.length())).mappable();
        }
        catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static long flashBase(List<Option> options) throws IOException {
        Option option = findFlashBase(options);
        if (option == null || !(option.getValue() instanceof Long value)) {
            throw new IOException("Missing valid ESP8266 flash base option");
        }
        return value;
    }

    private static Option findFlashBase(List<Option> options) {
        return options.stream().filter(option -> FLASH_BASE_OPTION.equals(option.getName()))
            .findFirst().orElse(null);
    }

    private static byte[] readBounded(ByteProvider provider) throws IOException {
        long length = provider.length();
        if (length > ParserLimits.defaults().maxInputBytes() || length > Integer.MAX_VALUE) {
            throw new IOException("ESP8266 image exceeds the configured input-byte limit");
        }
        return provider.readBytes(0, length);
    }
}
