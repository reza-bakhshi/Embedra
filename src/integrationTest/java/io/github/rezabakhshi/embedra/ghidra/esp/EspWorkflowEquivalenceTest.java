package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.targets.esp.Esp32S3TargetProvider;
import io.github.rezabakhshi.embedra.targets.esp.EspressifChipIdRegistry;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.List;
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
        EspApplicationImportService workflow = new EspApplicationImportService();
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
        }
        finally {
            Locale.setDefault(originalLocale);
            TimeZone.setDefault(originalTimeZone);
        }
    }

    @Test
    void malformedCorpusProducesTypedFailuresWithoutPartialProgramMutation()
            throws Exception {
        Esp32S3TargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        headlessProgram = program("Malformed headless import", provider, HEADLESS_CONSUMER);
        EspApplicationImportService workflow = new EspApplicationImportService();
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
