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
import io.github.rezabakhshi.embedra.targets.esp.Esp32S3TargetProvider;
import io.github.rezabakhshi.embedra.targets.esp.EspressifChipIdRegistry;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/** Ghidra loader entry point for validated ESP32-S3 application images. */
public final class EspApplicationImageLoader extends AbstractLibrarySupportLoader {
    public static final String APPLY_ESP32S3_PACKS_OPTION =
        "Apply verified ESP32-S3 ROM, peripheral, and SVD packs"
            + " (explicit revision assertion)";

    private static final int ESP32_S3_CHIP_ID = 9;

    private final Esp32S3TargetProvider targetProvider = new Esp32S3TargetProvider(
        EspressifChipIdRegistry.loadBundled());

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
            Boolean.FALSE, "Embedra ESP32-S3 enrichment",
            "Explicitly apply provenance-checked common ESP32-S3 data; "
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
            return "ESP32-S3 pack option must have a Boolean value";
        }
        return null;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
            throws IOException {
        byte[] input = readBounded(provider);
        try {
            if (isStandaloneImage(input)) {
                EspImage image = EspImageParser.parseForChip(input, ESP32_S3_CHIP_ID,
                    ParserLimits.defaults(), CancellationToken.none());
                if (!targetProvider.supports(image).supported()) {
                    return List.of();
                }
            }
            else {
                EspFullFlashWorkspacePlanner.plan(input, ParserLimits.defaults(),
                    CancellationToken.none());
            }
            LanguageSelection language = targetProvider.language();
            return List.of(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair(language.languageId(),
                    language.compilerSpecId()), true));
        }
        catch (DiagnosticException exception) {
            return List.of();
        }
    }

    @Override
    protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] input = readBounded(settings.provider());
        if (isStandaloneImage(input)) {
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
            EspImportWorkflowResult result = new EspApplicationImportService().importImage(
                program, input, settings.monitor());
            settings.log().appendMsg(getName(), "Mapped "
                + result.importReport().segments().size() + " validated segments for "
                + result.importReport().deviceId());
            applySelectedEnrichment(program, settings);
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
                    EspImportWorkflowResult result;
                    try {
                        result = new EspApplicationImportService().importImage(program,
                            executable.bytes(), settings.monitor(),
                            EspFlashProgramProvenance.from(workspace, executable));
                    }
                    catch (DiagnosticException failure) {
                        throw diagnosticIOException(failure);
                    }
                    settings.log().appendMsg(getName(), "Mapped "
                        + result.importReport().segments().size() + " validated segments for "
                        + childName + " from flash offset 0x"
                        + Long.toHexString(executable.flashRange().offset()));
                    applySelectedEnrichment(program, childSettings);
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

    private static boolean isStandaloneImage(byte[] input) {
        if (EspImageDetector.detect(input) != EspImageDetection.MATCH) {
            return false;
        }
        try {
            EspImageParser.parseForChip(input, ESP32_S3_CHIP_ID,
                ParserLimits.defaults(), CancellationToken.none());
            return true;
        }
        catch (DiagnosticException failure) {
            return false;
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

    private void applySelectedEnrichment(Program program, ImporterSettings settings)
            throws IOException, CancelledException {
        Option option = findOption(settings.options());
        if (option == null || !Boolean.TRUE.equals(option.getValue())) {
            return;
        }
        try {
            CancellationToken cancellation = settings.monitor()::isCancelled;
            Esp32S3BundledPacks packs = Esp32S3BundledPacks.load(cancellation);
            EspSvdApplicationReport svd = new Esp32S3SvdApplicator().apply(program,
                packs.svd(), settings.monitor());
            EspPackApplicationReport symbols = new Esp32S3PackApplicator().apply(program,
                packs.rom(), packs.peripherals(), settings.monitor());
            settings.log().appendMsg(getName(), "Applied explicit ESP32-S3 enrichment: "
                + symbols.createdSymbols().size() + " ROM/header symbols, "
                + svd.createdDataAddresses().size() + " SVD registers, "
                + svd.createdComments() + " SVD descriptions; provenance stored in program");
        }
        catch (DiagnosticException | EspMappingException exception) {
            throw new IOException("Explicit ESP32-S3 pack application failed: "
                + exception.getMessage(), exception);
        }
    }

    private static Option findOption(List<Option> options) {
        return options.stream().filter(option ->
            APPLY_ESP32S3_PACKS_OPTION.equals(option.getName())).findFirst().orElse(null);
    }

    private static byte[] readBounded(ByteProvider provider) throws IOException {
        long length = provider.length();
        if (length > ParserLimits.defaults().maxInputBytes() || length > Integer.MAX_VALUE) {
            throw new IOException("ESP image exceeds the configured input-byte limit");
        }
        return provider.readBytes(0, length);
    }
}
