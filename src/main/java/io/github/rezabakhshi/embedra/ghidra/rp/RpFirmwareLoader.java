package io.github.rezabakhshi.embedra.ghidra.rp;

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
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Family;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Image;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Parser;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2040Boot2Checksum;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350Architecture;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350BootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadataParser;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Ghidra loader entry point for Raspberry Pi UF2 and raw XIP / internal-flash firmware images.
 */
public final class RpFirmwareLoader extends AbstractLibrarySupportLoader {

    public static final String TARGET_PART_OPTION = "Target Silicon Part (optional override)";

    public static final String BOARD_PROFILE_OPTION = "Board Profile (optional override)";

    private final RpFirmwareImportService importService;

    public RpFirmwareLoader() {
        this(new RpFirmwareImportService());
    }

    public RpFirmwareLoader(RpFirmwareImportService importService) {
        this.importService = importService;
    }

    @Override
    public String getName() {
        return "Embedra Raspberry Pi Firmware";
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
                "Embedra RP target", "Explicitly override target silicon part (e.g. RP2040, RP2350A, RP2354A)"));
        options.add(new Option(BOARD_PROFILE_OPTION, String.class, "",
                "Embedra RP target", "Explicitly override board profile (e.g. pico, pico_w, pico2, pico2_w)"));
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

        RpDeviceCatalog catalog = RpFirmwareImportService.loadDefaultCatalogSafe();
        if (catalog.siliconRecords().isEmpty()) {
            return "Raspberry Pi device catalog is unavailable";
        }
        for (Option opt : options) {
            if (TARGET_PART_OPTION.equals(opt.getName())) {
                String val = (String) opt.getValue();
                if (val != null && !val.isBlank() && catalog.findExactPart(val.trim()).isEmpty()) {
                    return "Unknown Raspberry Pi silicon part: " + val;
                }
            } else if (BOARD_PROFILE_OPTION.equals(opt.getName())) {
                String val = (String) opt.getValue();
                if (val != null && !val.isBlank() && catalog.findBoardProfile(val.trim()).isEmpty()) {
                    return "Unknown Raspberry Pi board profile: " + val;
                }
            }
        }

        String targetPart = findStringOption(options, TARGET_PART_OPTION);
        String boardProfile = findStringOption(options, BOARD_PROFILE_OPTION);
        if (!targetPart.isBlank() && !boardProfile.isBlank()) {
            Optional<RpBoardProfile> profileOpt = catalog.findBoardProfile(boardProfile);
            if (profileOpt.isPresent() && !profileOpt.get().siliconPart().equalsIgnoreCase(targetPart)) {
                return "Board profile '" + boardProfile + "' targets " + profileOpt.get().siliconPart()
                        + ", but conflicting silicon part '" + targetPart + "' was specified";
            }
        }
        return null;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        byte[] input = readBounded(provider);

        // 1. Check UF2 container format
        if (RpFirmwareImportService.isUf2Candidate(input)) {
            if (!RpFirmwareImportService.isUf2Format(input)) {
                return List.of();
            }
            try {
                RpUf2Image image = RpUf2Parser.parse(input, ParserLimits.defaults(), CancellationToken.none());
                return List.of(new LoadSpec(this, 0, specForFamily(image.family()), true));
            } catch (DiagnosticException | IllegalArgumentException e) {
                return List.of();
            }
        }

        // 2. Check Raw RP2350 / RP2354 with IMAGE_DEF marker (0xffffded3)
        try {
            Rp2350BootMetadata meta2350 = RpBootMetadataParser.parseRp2350(
                    input, RpBootMetadataParser.FLASH_BASE, false);
            LanguageCompilerSpecPair pair = (meta2350.architecture() == Rp2350Architecture.RISCV)
                    ? new LanguageCompilerSpecPair("RISCV:LE:32:default", "gcc")
                    : new LanguageCompilerSpecPair("ARM:LE:32:v8-m", "default");
            return List.of(new LoadSpec(this, 0, pair, true));
        } catch (DiagnosticException ignored) {
            // Not RP2350
        }

        // 3. Check Raw RP2040 with boot2 stage (256 bytes) or vector table
        if (input.length >= Rp2040Boot2Checksum.BOOT2_SIZE) {
            try {
                var meta2040 = RpBootMetadataParser.parseRp2040(input, RpBootMetadataParser.FLASH_BASE);
                if (meta2040.isCrcValid() || meta2040.isPlaceholder() || meta2040.isVectorTableValid()) {
                    return List.of(new LoadSpec(this, 0,
                            new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default"), true));
                }
            } catch (DiagnosticException ignored) {
                // Not RP2040
            }
        }

        return List.of();
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] input = readBounded(settings.provider());
        String targetPart = findStringOption(settings.options(), TARGET_PART_OPTION);
        String boardProfile = findStringOption(settings.options(), BOARD_PROFILE_OPTION);

        if (targetPart.isBlank() && !boardProfile.isBlank()) {
            RpFirmwareImportService.loadDefaultCatalogSafe().findBoardProfile(boardProfile)
                    .ifPresent(profile -> settings.options().forEach(o -> {
                        if (TARGET_PART_OPTION.equals(o.getName())) {
                            o.setValue(profile.siliconPart());
                        }
                    }));
        }

        RpImportReport report = importService.importFirmware(
                program,
                input,
                targetPart,
                boardProfile,
                settings.monitor());

        settings.log().appendMsg(getName(), "Mapped " + report.mappedSegmentsCount()
                + " validated segments for " + report.targetPart() + " (" + report.series()
                + ") into " + report.languageId());
    }

    private static LanguageCompilerSpecPair specForFamily(RpUf2Family family) {
        if (family == RpUf2Family.RP2040) {
            return new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default");
        } else if (family == RpUf2Family.RP2350_RISCV) {
            return new LanguageCompilerSpecPair("RISCV:LE:32:default", "gcc");
        }
        return new LanguageCompilerSpecPair("ARM:LE:32:v8-m", "default");
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
            throw new IOException("Raspberry Pi firmware image exceeds configured input-byte limit");
        }
        return provider.readBytes(0, length);
    }
}
