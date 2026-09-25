package io.github.rezabakhshi.embedra.ghidra.esp;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.Option;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.framework.model.DomainObject;
import ghidra.util.exception.CancelledException;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageDetection;
import io.github.rezabakhshi.embedra.formats.esp.EspImageDetector;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.formats.esp.EspExtractedExecutable;
import io.github.rezabakhshi.embedra.formats.esp.EspExecutableRole;
import io.github.rezabakhshi.embedra.formats.esp.EspFullFlashWorkspace;
import io.github.rezabakhshi.embedra.formats.esp.EspFullFlashWorkspacePlanner;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.esp.EspTargetProvider;
import io.github.rezabakhshi.embedra.targets.esp.EspTargetProviders;
import io.github.rezabakhshi.embedra.targets.esp.EspTargetResolution;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** Ghidra loader entry point for validated, independently supported ESP images. */
public final class EspApplicationImageLoader extends AbstractLibrarySupportLoader {
    public static final String APPLY_ESP32S3_PACKS_OPTION =
        "Apply verified target ROM, peripheral, and SVD packs"
            + " (explicit revision assertion)";

    public static final String ENRICHMENT_DISABLED_CODE = "ESP32S3_ENRICHMENT_DISABLED";

    public static final String ENRICHMENT_APPLIED_CODE = "ESP32S3_ENRICHMENT_APPLIED";

    public static final String ENRICHMENT_OPTIONS = "Embedra ESP32-S3 Import";

    public static final String ESP_ENRICHMENT_OPTIONS = "Embedra ESP Import";

    @Override
    public String getName() {
        return "Embedra ESP Application Image";
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean loadIntoProgram,
            boolean mirrorFsLayout) {
        List<Option> options = new ArrayList<>(super.getDefaultOptions(provider, loadSpec,
            domainObject, loadIntoProgram, mirrorFsLayout));
        options.add(new Option(APPLY_ESP32S3_PACKS_OPTION, Boolean.class,
            Boolean.FALSE, "Embedra ESP enrichment",
            "Explicitly apply provenance-checked common target data; "
                + "silicon revision is not inferred"));
        return options;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
            List<Option> options, Program program) {
        String inherited = super.validateOptions(provider, loadSpec, options, program);
        if (inherited != null) {
            return inherited;
        }
        Option selected = findOption(options);
        if (selected == null || !(selected.getValue() instanceof Boolean)) {
            return "ESP pack option must have a Boolean value";
        }
        return null;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
            throws IOException {
        byte[] input = readBounded(provider);
        try {
            EspTargetResolution target;
            Optional<EspTargetResolution> standalone = standaloneTarget(input);
            if (standalone.isPresent()) {
                target = standalone.orElseThrow();
            }
            else {
                EspFullFlashWorkspace workspace = EspFullFlashWorkspacePlanner.plan(input,
                    ParserLimits.defaults(), CancellationToken.none());
                target = resolveTarget(workspace.executables().get(0).image());
                boolean mixedTargets = workspace.executables().stream().anyMatch(executable ->
                    executable.image().header().chipId() != target.provider().chipId());
                if (mixedTargets) {
                    return List.of();
                }
            }
            LanguageSelection language = target.provider().language();
            return List.of(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair(language.languageId(),
                    language.compilerSpecId()), true));
        }
        catch (DiagnosticException | IllegalArgumentException exception) {
            return List.of();
        }
    }

    @Override
    protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] input = readBounded(settings.provider());
        if (standaloneTarget(input).isPresent()) {
            return super.loadProgram(settings);
        }
        try {
            EspFullFlashWorkspace workspace = EspFullFlashWorkspacePlanner.plan(input,
                ParserLimits.defaults(), settings.monitor()::isCancelled);
            return loadWorkspace(workspace, settings);
        }
        catch (DiagnosticException exception) {
            throw diagnosticIOException(exception);
        }
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] input = readBounded(settings.provider());
        CancellationToken cancellation = settings.monitor()::isCancelled;
        try {
            cancellation.throwIfCancellationRequested();
            EspTargetProvider target = resolveTarget(EspImageParser.parse(input,
                ParserLimits.defaults(), cancellation)).provider();
            EspImportWorkflowResult result = new EspApplicationImportService(target)
                .importImage(program, input, settings.monitor());
            settings.log().appendMsg(getName(), "Mapped "
                + result.importReport().segments().size() + " validated segments for "
                + result.importReport().deviceId());
            applySelectedEnrichment(program, target, settings);
        }
        catch (DiagnosticException exception) {
            throw diagnosticIOException(exception);
        }
    }

    private List<Loaded<Program>> loadWorkspace(EspFullFlashWorkspace workspace,
            ImporterSettings settings) throws IOException, CancelledException {
        List<Loaded<Program>> loadedPrograms = new ArrayList<>();
        List<EspExtractedExecutable> ordered = workspace.executables().stream()
            .sorted(Comparator.comparing(executable ->
                executable.role() == EspExecutableRole.BOOTLOADER))
            .toList();
        try {
            for (EspExtractedExecutable executable : ordered) {
                settings.monitor().checkCancelled();
                String childName = childName(settings.importNameOnly(), executable.name());
                ByteArrayProvider childProvider = new ByteArrayProvider(childName,
                    executable.bytes());
                ImporterSettings childSettings = new ImporterSettings(childProvider,
                    childName, settings.project(), settings.projectRootPath(),
                    settings.mirrorFsLayout(), settings.loadSpec(), settings.options(),
                    settings.consumer(), settings.log(), settings.monitor());
                Program program = createProgram(childSettings);
                boolean retained = false;
                try {
                    EspTargetProvider target = resolveTarget(executable.image()).provider();
                    EspImportWorkflowResult result;
                    try {
                        result = new EspApplicationImportService(target).importImage(program,
                            executable.bytes(), settings.monitor(),
                            EspFlashProgramProvenance.from(workspace, executable));
                    }
                    catch (DiagnosticException failure) {
                        throw diagnosticIOException(failure);
                    }
                    settings.log().appendMsg(getName(), "Mapped "
                        + result.importReport().segments().size() + " validated segments for "
                        + target.providerId() + " "
                        + executable.role().name().toLowerCase(Locale.ROOT)
                        + " image from flash offset 0x"
                        + Long.toHexString(executable.flashRange().offset()));
                    applySelectedEnrichment(program, target, childSettings);
                    loadedPrograms.add(new Loaded<>(program, childSettings));
                    retained = true;
                }
                finally {
                    if (!retained) {
                        program.release(settings.consumer());
                    }
                }
            }
            settings.log().appendMsg(getName(), "Planned "
                + workspace.dataPartitions().size()
                + " opaque data partitions; no files were written");
            return loadedPrograms;
        }
        catch (RuntimeException | IOException | CancelledException failure) {
            loadedPrograms.forEach(Loaded::close);
            throw failure;
        }
    }

    private static EspTargetResolution resolveTarget(EspImage image) {
        EspTargetResolution resolution = EspTargetProviders.resolver().resolve(image)
            .orElseThrow(() ->
            new IllegalArgumentException("ESP image has no supported target provider"));
        boolean segmentsMappable = image.segments().stream().allMatch(segment ->
            resolution.provider().classify(segment.targetRange()).mappable());
        if (!segmentsMappable || !resolution.provider().validateEntry(
                image.header().entryPoint(), image).accepted()) {
            throw new IllegalArgumentException(
                "ESP image ranges do not match the selected target provider");
        }
        return resolution;
    }

    private static Optional<EspTargetResolution> standaloneTarget(byte[] input) {
        if (EspImageDetector.detect(input) != EspImageDetection.MATCH) {
            return Optional.empty();
        }
        try {
            EspImage image = EspImageParser.parse(input, ParserLimits.defaults(),
                CancellationToken.none());
            return Optional.of(resolveTarget(image));
        }
        catch (DiagnosticException | IllegalArgumentException failure) {
            return Optional.empty();
        }
    }

    private static String childName(String importName, String executableName) {
        String base = importName;
        int dot = base.lastIndexOf('.');
        if (dot > 0) {
            base = base.substring(0, dot);
        }
        String safeRole = executableName.toLowerCase(Locale.ROOT)
            .replaceAll("[^a-z0-9._-]", "_");
        return base + "_" + safeRole;
    }

    private static IOException diagnosticIOException(DiagnosticException exception) {
        return new IOException(exception.diagnostic().code().id() + ": "
            + exception.getMessage(), exception);
    }

    private void applySelectedEnrichment(Program program, EspTargetProvider target,
            ImporterSettings settings)
            throws IOException, CancelledException {
        String disabledCode = enrichmentCode(target, false);
        String appliedCode = enrichmentCode(target, true);
        Option option = findOption(settings.options());
        if (option == null || !Boolean.TRUE.equals(option.getValue())) {
            recordEnrichmentSelection(program, target, false);
            settings.log().appendMsg(getName(), disabledCode
                + ": Raw mapping succeeded. Revision-dependent ROM/peripheral/SVD "
                + "enrichment was not applied; register names and Embedra crypto "
                + "analysis are unavailable. Confirm applicability, then explicitly "
                + "select the ESP enrichment import option.");
            return;
        }
        try {
            CancellationToken cancellation = settings.monitor()::isCancelled;
            TargetPackConfiguration configuration = packConfiguration(target);
            Esp32S3BundledPacks packs = Esp32S3BundledPacks.load(
                configuration.deviceId(), cancellation);
            EspSvdApplicationReport svd = new Esp32S3SvdApplicator(
                configuration.deviceId(), configuration.displayName()).apply(program,
                    packs.svd(), settings.monitor());
            EspPackApplicationReport symbols = new Esp32S3PackApplicator(
                configuration.deviceId(), configuration.displayName(),
                configuration.romCodeLength()).apply(program, packs.rom(),
                    packs.peripherals(), settings.monitor());
            recordEnrichmentSelection(program, target, true);
            settings.log().appendMsg(getName(), appliedCode
                + ": Applied explicit " + configuration.displayName() + " enrichment: "
                + symbols.createdSymbols().size() + " ROM/header symbols, "
                + svd.createdDataAddresses().size() + " SVD registers, "
                + svd.createdComments() + " SVD descriptions; provenance stored in program");
        }
        catch (DiagnosticException | EspMappingException exception) {
            throw new IOException("Explicit ESP pack application failed: "
                + exception.getMessage(), exception);
        }
    }

    private static void recordEnrichmentSelection(Program program,
            EspTargetProvider target, boolean selected) {
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Record ESP enrichment selection")) {
            var options = program.getOptions(enrichmentOptions(target));
            options.setBoolean("Selected", selected);
            options.setString("Target Provider", target.providerId());
            options.setString("Diagnostic Code", enrichmentCode(target, selected));
            transaction.commit();
        }
    }

    private static String enrichmentOptions(EspTargetProvider target) {
        return target.chipId() == 9 ? ENRICHMENT_OPTIONS : ESP_ENRICHMENT_OPTIONS;
    }

    private static String enrichmentCode(EspTargetProvider target, boolean selected) {
        if (target.chipId() == 9) {
            return selected ? ENRICHMENT_APPLIED_CODE : ENRICHMENT_DISABLED_CODE;
        }
        String providerId = target.providerId();
        String deviceCode = providerId.substring(providerId.lastIndexOf('.') + 1)
            .toUpperCase(Locale.ROOT)
            .replace("-", "");
        return deviceCode + (selected ? "_ENRICHMENT_APPLIED"
            : "_ENRICHMENT_DISABLED");
    }

    private static Option findOption(List<Option> options) {
        return options.stream().filter(option ->
            APPLY_ESP32S3_PACKS_OPTION.equals(option.getName())).findFirst().orElse(null);
    }

    private static TargetPackConfiguration packConfiguration(EspTargetProvider target) {
        return switch (target.chipId()) {
            case 0 -> new TargetPackConfiguration("esp32", "ESP32", 0x70000L);
            case 2 -> new TargetPackConfiguration("esp32s2", "ESP32-S2", 0x20000L);
            case 9 -> new TargetPackConfiguration("esp32s3", "ESP32-S3", 0x60000L);
            default -> throw new IllegalArgumentException(
                "No enrichment packs exist for chip ID " + target.chipId());
        };
    }

    private static byte[] readBounded(ByteProvider provider) throws IOException {
        long length = provider.length();
        if (length > ParserLimits.defaults().maxInputBytes() || length > Integer.MAX_VALUE) {
            throw new IOException("ESP image exceeds the configured input-byte limit");
        }
        return provider.readBytes(0, length);
    }

    private record TargetPackConfiguration(
            String deviceId, String displayName, long romCodeLength) {
    }
}
