package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.ghidra.equivalence.GhidraProgramEquivalenceAssertor;
import io.github.rezabakhshi.embedra.ghidra.esp8266.Esp8266LegacyImageLoader;
import io.github.rezabakhshi.embedra.targets.esp.Esp32S3TargetProvider;
import io.github.rezabakhshi.embedra.targets.esp.EspressifChipIdRegistry;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class EspWorkflowEquivalenceTest {
    private static final Object GUI_CONSUMER = new Object();

    private static final Object HEADLESS_CONSUMER = new Object();

    private ProgramDB guiProgram;

    private ProgramDB headlessProgram;

    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            String installDirectory = System.getenv("GHIDRA_INSTALL_DIR");
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDirectory)), configuration);
        }
        DefaultLanguageService.getLanguageService().getLanguageDescriptions(true);
    }

    @AfterEach
    void tearDown() {
        if (guiProgram != null) {
            guiProgram.release(GUI_CONSUMER);
        }
        if (headlessProgram != null) {
            headlessProgram.release(HEADLESS_CONSUMER);
        }
    }

    @Test
    void guiAndHeadlessInvocationsProduceByteIdenticalReportsAndSnapshots()
            throws Exception {
        Esp32S3TargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        guiProgram = program("GUI import", provider, GUI_CONSUMER);
        headlessProgram = program("Headless import", provider, HEADLESS_CONSUMER);
        byte[] input = fixture();
        EspApplicationImportService workflow = new EspApplicationImportService(provider);
        Locale originalLocale = Locale.getDefault();
        TimeZone originalTimeZone = TimeZone.getDefault();

        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tehran"));
            EspImportWorkflowResult gui = workflow.importImage(guiProgram, input,
                TaskMonitor.DUMMY);

            Locale.setDefault(Locale.JAPAN);
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Auckland"));
            EspImportWorkflowResult headless = workflow.importImage(headlessProgram, input,
                TaskMonitor.DUMMY);

            assertEquals(gui.canonicalReportJson(), headless.canonicalReportJson());
            assertEquals(gui.programSnapshotJson(), headless.programSnapshotJson());
            assertEquals(gui.executionTopology(), headless.executionTopology());
            assertEquals(1, gui.executionTopology().processors().size());
            assertEquals(3, gui.importReport().segments().size());
            assertEquals("embedra_t008_fixture",
                gui.appDescription().description().orElseThrow().projectName());
            assertFalse(gui.canonicalReportJson().contains("GUI import"));
            assertFalse(gui.canonicalReportJson().contains("Headless import"));
            assertFalse(gui.canonicalReportJson().contains("timestamp"));
            assertFalse(gui.canonicalReportJson().contains("hostPath"));

            // Assert deep program and snapshot equivalence
            GhidraProgramEquivalenceAssertor.assertProgramEquivalence(guiProgram, headlessProgram);
            GhidraProgramEquivalenceAssertor.assertWorkspaceSnapshotEquivalence(guiProgram, headlessProgram);
        }
        finally {
            Locale.setDefault(originalLocale);
            TimeZone.setDefault(originalTimeZone);
        }
    }

    @Test
    void testAllEspFamilyApplicationImagesEquivalence() throws Exception {
        List<String> devices = List.of(
            "esp32s3", "esp32", "esp32s2", "esp32c3", "esp32c2", "esp32c5",
            "esp32c6", "esp32c61", "esp32h2", "esp32h21", "esp32h4", "esp32p4",
            "esp32s31", "esp32e22");

        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        for (String deviceId : devices) {
            byte[] bytes = familyFixture(deviceId);
            ByteArrayProvider provider = new ByteArrayProvider(deviceId + ".bin", bytes);
            Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
            assertFalse(specs.isEmpty(), "Specs must be non-empty for " + deviceId);
            LoadSpec spec = specs.iterator().next();

            List<Option> guiOpts = loader.getDefaultOptions(provider, spec, null, false, false);
            List<Option> headlessOpts = loader.getDefaultOptions(provider, spec, null, false, false);

            runLoaderEquivalenceAssertion(loader, provider, spec, guiOpts, headlessOpts);
        }
    }

    @Test
    void testEsp32S3FullFlashDefaultFactoryEquivalence() throws Exception {
        byte[] flash = fullFlashFixture("default-factory.bin");
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("default-factory.bin", flash);
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty(), "Specs must be non-empty for full-flash");
        LoadSpec spec = specs.iterator().next();

        List<Option> guiOpts = loader.getDefaultOptions(provider, spec, null, false, false);
        List<Option> headlessOpts = loader.getDefaultOptions(provider, spec, null, false, false);

        runLoaderEquivalenceAssertion(loader, provider, spec, guiOpts, headlessOpts);
    }

    @Test
    void testEsp8266LegacyImagesEquivalence() throws Exception {
        List<String> standaloneFixtures = List.of(
            "esp8266-freestanding-v1-0x00000.bin",
            "esp8266-freestanding-v2-0x01000.bin"
        );

        Esp8266LegacyImageLoader loader = new Esp8266LegacyImageLoader();
        for (String fixtureName : standaloneFixtures) {
            byte[] bytes = esp8266Fixture(fixtureName);
            ByteArrayProvider provider = new ByteArrayProvider(fixtureName, bytes);
            Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
            assertFalse(specs.isEmpty(), "Specs must be non-empty for " + fixtureName);
            LoadSpec spec = specs.iterator().next();

            List<Option> guiOpts = loader.getDefaultOptions(provider, spec, null, false, false);
            List<Option> headlessOpts = loader.getDefaultOptions(provider, spec, null, false, false);

            runLoaderEquivalenceAssertion(loader, provider, spec, guiOpts, headlessOpts);
        }

        // Test the v1 raw IROM companion fixture
        String companionName = "esp8266-freestanding-v1-0x01010.bin";
        byte[] companionBytes = esp8266Fixture(companionName);
        ByteArrayProvider companionProvider = new ByteArrayProvider(companionName, companionBytes);
        ghidra.app.util.opinion.BinaryLoader binaryLoader = new ghidra.app.util.opinion.BinaryLoader();
        LoadSpec binarySpec = new LoadSpec(binaryLoader, 0,
            new ghidra.program.model.lang.LanguageCompilerSpecPair(
                new LanguageID("Xtensa:LE:32:default"),
                new CompilerSpecID("default")), false);
        List<Option> companionGuiOpts = binaryLoader.getDefaultOptions(
            companionProvider, binarySpec, null, false, false);
        List<Option> companionHeadlessOpts = binaryLoader.getDefaultOptions(
            companionProvider, binarySpec, null, false, false);
        Language xtensaLang = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("Xtensa:LE:32:default"));
        Address iromBase = xtensaLang.getAddressFactory().getDefaultAddressSpace().getAddress(0x40201010L);
        companionGuiOpts.stream()
            .filter(o -> ghidra.app.util.opinion.BinaryLoader.OPTION_NAME_BASE_ADDR.equals(o.getName()))
            .findFirst().orElseThrow().setValue(iromBase);
        companionHeadlessOpts.stream()
            .filter(o -> ghidra.app.util.opinion.BinaryLoader.OPTION_NAME_BASE_ADDR.equals(o.getName()))
            .findFirst().orElseThrow().setValue(iromBase);
        runLoaderEquivalenceAssertion(
            binaryLoader, companionProvider, binarySpec, companionGuiOpts, companionHeadlessOpts);
    }

    @Test
    void malformedCorpusProducesTypedFailuresWithoutPartialProgramMutation()
            throws Exception {
        Esp32S3TargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        headlessProgram = program("Malformed headless import", provider, HEADLESS_CONSUMER);
        EspApplicationImportService workflow = new EspApplicationImportService(provider);
        List<MalformedCase> cases = List.of(
            new MalformedCase("malformed-truncated-segment-data.bin",
                DiagnosticCode.ESP_SEGMENT_TRUNCATED),
            new MalformedCase("malformed-segment-length-overflow.bin",
                DiagnosticCode.ESP_SEGMENT_LENGTH_INVALID),
            new MalformedCase("malformed-overlapping-segments.bin",
                DiagnosticCode.ESP_SEGMENT_OVERLAP),
            new MalformedCase("malformed-wrong-chip.bin",
                DiagnosticCode.ESP_CHIP_MISMATCH),
            new MalformedCase("malformed-checksum.bin",
                DiagnosticCode.ESP_CHECKSUM_MISMATCH),
            new MalformedCase("malformed-digest.bin",
                DiagnosticCode.ESP_DIGEST_MISMATCH),
            new MalformedCase("malformed-entry-unaligned.bin",
                DiagnosticCode.ESP_ENTRY_INVALID),
            new MalformedCase("malformed-trailing-data.bin",
                DiagnosticCode.ESP_TRAILING_DATA));

        for (MalformedCase malformed : cases) {
            DiagnosticException failure = assertThrows(DiagnosticException.class,
                () -> workflow.importImage(headlessProgram,
                    malformedFixture(malformed.name()), TaskMonitor.DUMMY));
            assertEquals(malformed.code(), failure.diagnostic().code());
            assertEquals(0, headlessProgram.getMemory().getBlocks().length);
            assertFalse(headlessProgram.getSymbolTable().getExternalEntryPointIterator()
                .hasNext());
        }
    }

    private void runLoaderEquivalenceAssertion(
            Loader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> guiOpts,
            List<Option> headlessOpts) throws Exception {
        Locale originalLocale = Locale.getDefault();
        TimeZone originalTimeZone = TimeZone.getDefault();

        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tehran"));
            List<Program> guiPrograms = loadPrograms(loader, provider, spec, guiOpts, GUI_CONSUMER);

            Locale.setDefault(Locale.JAPAN);
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Auckland"));
            List<Program> headlessPrograms = loadPrograms(loader, provider, spec, headlessOpts, HEADLESS_CONSUMER);

            try {
                assertEquals(guiPrograms.size(), headlessPrograms.size(),
                    "Loaded program count must match identically");
                for (int i = 0; i < guiPrograms.size(); i++) {
                    Program gp = guiPrograms.get(i);
                    Program hp = headlessPrograms.get(i);
                    GhidraProgramEquivalenceAssertor.assertProgramEquivalence(gp, hp);
                    GhidraProgramEquivalenceAssertor.assertWorkspaceSnapshotEquivalence(gp, hp);
                }
            }
            finally {
                for (Program p : guiPrograms) {
                    p.release(GUI_CONSUMER);
                }
                for (Program p : headlessPrograms) {
                    p.release(HEADLESS_CONSUMER);
                }
            }
        }
        finally {
            Locale.setDefault(originalLocale);
            TimeZone.setDefault(originalTimeZone);
        }
    }

    private static List<Program> loadPrograms(
            Loader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> options,
            Object consumer) throws Exception {
        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, options, consumer, new MessageLog(), TaskMonitor.DUMMY);
        LoadResults<? extends DomainObject> results = loader.load(settings);
        List<Program> programs = new ArrayList<>();
        for (var loaded : results) {
            loaded.apply(d -> programs.add((Program) d));
        }
        return programs;
    }

    private static ProgramDB program(String name, Esp32S3TargetProvider provider,
            Object consumer) throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(provider.language().languageId()));
        CompilerSpec compiler = language.getCompilerSpecByID(
            new CompilerSpecID(provider.language().compilerSpecId()));
        return new ProgramDB(name, language, compiler, consumer);
    }

    private static byte[] fixture() throws IOException {
        try (InputStream input = EspWorkflowEquivalenceTest.class.getResourceAsStream(
                "/fixtures/esp32s3/esp32s3-freestanding-minimal.bin")) {
            assertNotNull(input, "missing T008 fixture");
            return input.readAllBytes();
        }
    }

    private static byte[] familyFixture(String deviceId) throws IOException {
        String resource = "/fixtures/" + deviceId + "/" + deviceId
            + "-freestanding-minimal.bin";
        try (InputStream input = EspWorkflowEquivalenceTest.class.getResourceAsStream(resource)) {
            assertNotNull(input, "missing fixture " + resource);
            return input.readAllBytes();
        }
    }

    private static byte[] fullFlashFixture(String name) throws IOException {
        String resource = "/fixtures/esp32s3/full-flash/" + name;
        try (InputStream input = EspWorkflowEquivalenceTest.class.getResourceAsStream(resource)) {
            assertNotNull(input, "missing full-flash fixture " + resource);
            return input.readAllBytes();
        }
    }

    private static byte[] esp8266Fixture(String name) throws IOException {
        String resource = "/fixtures/esp8266/" + name;
        try (InputStream input = EspWorkflowEquivalenceTest.class.getResourceAsStream(resource)) {
            assertNotNull(input, "missing esp8266 fixture " + resource);
            return input.readAllBytes();
        }
    }

    private static byte[] malformedFixture(String name) throws IOException {
        try (InputStream input = EspWorkflowEquivalenceTest.class.getResourceAsStream(
                "/fixtures/esp32s3/malformed/" + name)) {
            assertNotNull(input, "missing T009 fixture " + name);
            return input.readAllBytes();
        }
    }

    private record MalformedCase(String name, DiagnosticCode code) {
    }
}
