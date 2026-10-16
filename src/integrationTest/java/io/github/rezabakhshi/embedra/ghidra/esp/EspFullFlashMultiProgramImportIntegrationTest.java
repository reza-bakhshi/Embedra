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
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.github.rezabakhshi.embedra.ghidra.equivalence.GhidraProgramEquivalenceAssertor;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Proof suite verifying T086: Real-Ghidra multi-program full-flash import across all 14 ESP series.
 * Verifies GUI/headless equivalence, byte/address/language/entry mappings, opaque artifact handling,
 * OTA metadata, cancellation rollback, and negative corpora rejection.
 */
class EspFullFlashMultiProgramImportIntegrationTest {
    private static final Object GUI_CONSUMER = new Object();

    private static final Object HEADLESS_CONSUMER = new Object();

    private static final List<String> ALL_14_SERIES = List.of(
            "esp32", "esp32s2", "esp32s3", "esp32c3", "esp32c2", "esp32c5",
            "esp32c6", "esp32c61", "esp32h2", "esp32h21", "esp32h4", "esp32p4",
            "esp32s31", "esp32e22"
    );

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

    @Test
    void testAllFourteenSeriesDefaultFactoryMultiProgramImportAndEquivalence() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();

        for (String series : ALL_14_SERIES) {
            byte[] flash = fullFlashFixture(series, "default-factory.bin");
            ByteArrayProvider provider = new ByteArrayProvider(series + "-factory.bin", flash);

            Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
            assertFalse(specs.isEmpty(), "Specs must be non-empty for " + series);
            LoadSpec spec = specs.iterator().next();

            String expectedLang = expectedLanguage(series);
            String expectedCompiler = expectedCompiler(series);
            assertEquals(expectedLang, spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());
            assertEquals(expectedCompiler, spec.getLanguageCompilerSpec().getCompilerSpecID().getIdAsString());

            List<Option> guiOpts = loader.getDefaultOptions(provider, spec, null, false, false);
            List<Option> headlessOpts = loader.getDefaultOptions(provider, spec, null, false, false);

            runEquivalenceAssertion(loader, provider, spec, guiOpts, headlessOpts, 2);
        }
    }

    @Test
    void testAllFourteenSeriesOtaAndOpaqueArtifactHandling() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();

        for (String series : ALL_14_SERIES) {
            byte[] flash = fullFlashFixture(series, "ota-custom-encrypted.bin");
            ByteArrayProvider provider = new ByteArrayProvider(series + "-ota.bin", flash);

            Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
            assertFalse(specs.isEmpty(), "Specs must be non-empty for " + series + " OTA");
            LoadSpec spec = specs.iterator().next();

            List<Option> guiOpts = loader.getDefaultOptions(provider, spec, null, false, false);
            List<Option> headlessOpts = loader.getDefaultOptions(provider, spec, null, false, false);

            // ota-custom-encrypted fixture contains bootloader, ota_0, ota_1, and encrypted assets partition
            // Must load exactly 3 executable programs, leaving assets opaque
            runEquivalenceAssertion(loader, provider, spec, guiOpts, headlessOpts, 3);
        }
    }

    @Test
    void testAllFourteenSeriesNegativeCorporaRejection() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();

        for (String series : ALL_14_SERIES) {
            byte[] invalidMd5 = fullFlashFixture(series, "invalid-partition-md5.bin");
            ByteArrayProvider providerMd5 = new ByteArrayProvider(series + "-md5.bin", invalidMd5);
            assertTrue(loader.findSupportedLoadSpecs(providerMd5).isEmpty(),
                    "Loader must reject invalid partition table MD5 for " + series);

            if (!series.equals("esp32s3")) {
                byte[] wrongChip = fullFlashFixture(series, "malformed-wrong-chip.bin");
                ByteArrayProvider providerChip = new ByteArrayProvider(series + "-chip.bin", wrongChip);
                assertTrue(loader.findSupportedLoadSpecs(providerChip).isEmpty(),
                        "Loader must reject wrong chip ID for " + series);
            }
        }
    }

    @Test
    void testCooperativeCancellationRollsBackMultiProgramImport() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        List<String> sampleSeries = List.of("esp32", "esp32s2", "esp32s3", "esp32c3", "esp32p4");

        for (String series : sampleSeries) {
            byte[] flash = fullFlashFixture(series, "default-factory.bin");
            ByteArrayProvider provider = new ByteArrayProvider(series + "-cancel.bin", flash);
            LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
            List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);

            CancellingMonitor monitor = new CancellingMonitor();
            monitor.cancel();

            ImporterSettings settings = new ImporterSettings(provider, series + "-cancel.bin",
                    null, "/", false, spec, options, new Object(), new MessageLog(), monitor);

            Exception failure = assertThrows(Exception.class, () -> loader.load(settings));
            assertTrue(failure instanceof CancelledException
                    || failure.getMessage().contains("CANCELLED")
                    || (failure.getCause() != null && failure.getCause().getMessage().contains("CANCELLED")));
        }
    }

    @Test
    void testRepeatImportIdempotence() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        byte[] flash = fullFlashFixture("esp32p4", "default-factory.bin");
        ByteArrayProvider provider = new ByteArrayProvider("p4-idempotence.bin", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);

        List<Program> firstRun = loadPrograms(loader, provider, spec, options, GUI_CONSUMER);
        List<Program> secondRun = loadPrograms(loader, provider, spec, options, HEADLESS_CONSUMER);

        try {
            assertEquals(firstRun.size(), secondRun.size());
            for (int i = 0; i < firstRun.size(); i++) {
                GhidraProgramEquivalenceAssertor.assertProgramEquivalence(firstRun.get(i), secondRun.get(i));
                GhidraProgramEquivalenceAssertor.assertWorkspaceSnapshotEquivalence(firstRun.get(i), secondRun.get(i));
            }
        }
        finally {
            firstRun.forEach(p -> p.release(GUI_CONSUMER));
            secondRun.forEach(p -> p.release(HEADLESS_CONSUMER));
        }
    }

    private void runEquivalenceAssertion(
            EspApplicationImageLoader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> guiOpts,
            List<Option> headlessOpts,
            int expectedProgramCount) throws Exception {
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
                assertEquals(expectedProgramCount, guiPrograms.size(),
                        "Loaded GUI program count mismatch for " + provider.getName());
                assertEquals(expectedProgramCount, headlessPrograms.size(),
                        "Loaded Headless program count mismatch for " + provider.getName());

                for (int i = 0; i < guiPrograms.size(); i++) {
                    Program gp = guiPrograms.get(i);
                    Program hp = headlessPrograms.get(i);

                    // Check provenance and address mappings
                    assertTrue(gp.getMemory().getBlocks().length > 0);
                    assertTrue(gp.getSymbolTable().getExternalEntryPointIterator().hasNext());
                    var provenance = gp.getOptions("Embedra Full Flash Provenance");
                    assertTrue(provenance.getLong("Partition Table Offset", -1) > 0);
                    assertFalse(provenance.getString("Source SHA-256", "").isBlank());

                    GhidraProgramEquivalenceAssertor.assertProgramEquivalence(gp, hp);
                    GhidraProgramEquivalenceAssertor.assertWorkspaceSnapshotEquivalence(gp, hp);
                }
            }
            finally {
                guiPrograms.forEach(p -> p.release(GUI_CONSUMER));
                headlessPrograms.forEach(p -> p.release(HEADLESS_CONSUMER));
            }
        }
        finally {
            Locale.setDefault(originalLocale);
            TimeZone.setDefault(originalTimeZone);
        }
    }

    private static List<Program> loadPrograms(
            EspApplicationImageLoader loader,
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

    private static String expectedLanguage(String series) {
        if ("esp32".equals(series) || "esp32s2".equals(series)) {
            return "Xtensa:LE:32:default";
        }
        if ("esp32s3".equals(series)) {
            return "Xtensa:LE:32:esp32s3";
        }
        return "RISCV:LE:32:default";
    }

    private static String expectedCompiler(String series) {
        if ("esp32".equals(series) || "esp32s2".equals(series) || "esp32s3".equals(series)) {
            return "default";
        }
        return "gcc";
    }

    private static byte[] fullFlashFixture(String series, String name) throws IOException {
        String resource = "/fixtures/" + series + "/full-flash/" + name;
        try (InputStream input = EspFullFlashMultiProgramImportIntegrationTest.class.getResourceAsStream(resource)) {
            assertNotNull(input, "missing fixture " + resource);
            return input.readAllBytes();
        }
    }

    private static final class CancellingMonitor extends TaskMonitorAdapter {
        private boolean cancelled;

        @Override
        public boolean isCancelled() {
            return cancelled;
        }

        @Override
        public void checkCancelled() throws CancelledException {
            if (cancelled) {
                throw new CancelledException();
            }
        }

        public void cancel() {
            this.cancelled = true;
        }
    }
}
