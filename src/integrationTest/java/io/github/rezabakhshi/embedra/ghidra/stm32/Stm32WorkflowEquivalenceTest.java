package io.github.rezabakhshi.embedra.ghidra.stm32;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.IntelHexLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32RawBinPlan;
import io.github.rezabakhshi.embedra.ghidra.equivalence.GhidraProgramEquivalenceAssertor;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.mp.Stm32MpDeviceTreeParser;
import io.github.rezabakhshi.embedra.targets.stm32.mp.Stm32MpDeviceTreePlan;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Systematic GUI/headless equivalence test suite across all representative STM32 silicon families and formats.
 */
public class Stm32WorkflowEquivalenceTest {

    private static final Object GUI_CONSUMER = new Object();

    private static final Object HEADLESS_CONSUMER = new Object();

    private static final record Stm32PartSpec(String family, String folder, String exactPart, long flashBase) {
    }

    private static final List<Stm32PartSpec> REPRESENTATIVE_PARTS = List.of(
        // Cortex-M0/M0+
        new Stm32PartSpec("Cortex-M0+", "stm32c0", "STM32C051C8T6", 0x08000000L),
        new Stm32PartSpec("Cortex-M0+", "stm32c0", "STM32C071RBT6", 0x08000000L),
        new Stm32PartSpec("Cortex-M0+", "stm32c0", "STM32C092RCT6", 0x08000000L),
        new Stm32PartSpec("Cortex-M0+", "stm32-core-samples", "STM32G0B1RET6", 0x08000000L),
        new Stm32PartSpec("Cortex-M0+", "stm32-core-samples", "STM32U031R8T6", 0x08000000L),

        // Cortex-M3
        new Stm32PartSpec("Cortex-M3", "stm32f103", "STM32F103C8T6", 0x08000000L),
        new Stm32PartSpec("Cortex-M3", "stm32f103", "STM32F103CBT6", 0x08000000L),
        new Stm32PartSpec("Cortex-M3", "stm32f103", "STM32F103RBT6", 0x08000000L),
        new Stm32PartSpec("Cortex-M3", "stm32-core-samples", "STM32F207ZGT6", 0x08000000L),

        // Cortex-M4
        new Stm32PartSpec("Cortex-M4", "stm32-core-samples", "STM32F401RET6", 0x08000000L),
        new Stm32PartSpec("Cortex-M4", "stm32-core-samples", "STM32G431RBT6", 0x08000000L),
        new Stm32PartSpec("Cortex-M4", "stm32-core-samples", "STM32L412KBU3", 0x08000000L),
        new Stm32PartSpec("Cortex-M4", "stm32-core-samples", "STM32L4P5CGU6", 0x08000000L),
        new Stm32PartSpec("Cortex-M4", "stm32-core-samples", "STM32WB15CCU6", 0x08000000L),
        new Stm32PartSpec("Cortex-M4", "stm32-core-samples", "STM32WL33CCV6TR", 0x10040000L),

        // Cortex-M7
        new Stm32PartSpec("Cortex-M7", "stm32-core-samples", "STM32F756ZGT6", 0x08000000L),
        new Stm32PartSpec("Cortex-M7", "stm32-core-samples", "STM32H735IGK6", 0x08000000L),

        // Cortex-M33 (TrustZone)
        new Stm32PartSpec("Cortex-M33", "stm32-core-samples", "STM32H503RBT6", 0x08000000L),
        new Stm32PartSpec("Cortex-M33", "stm32-core-samples", "STM32L562QEI6Q", 0x08000000L),
        new Stm32PartSpec("Cortex-M33", "stm32-core-samples", "STM32U545RET6Q", 0x08000000L),
        new Stm32PartSpec("Cortex-M33", "stm32-core-samples", "STM32WBA25CEU7", 0x08000000L),

        // Cortex-M55 / N6
        new Stm32PartSpec("Cortex-M55", "stm32-core-samples", "STM32N657X0H3Q", 0x34000000L)
    );

    private static Stm32CuratedPartIds selection;

    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                    new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),
                    configuration);
        }
        selection = Stm32CuratedPartIds.load(
            Path.of("catalogs/stm32/2026-09-29/selection.json"),
            ParserLimits.defaults(), CancellationToken.none());
    }

    @Test
    void testAllStm32RawBinaryGuiAndHeadlessEquivalence() throws Exception {
        for (Stm32PartSpec spec : REPRESENTATIVE_PARTS) {
            byte[] bytes = fixture(spec.folder(), spec.exactPart() + ".bin");
            Stm32RawBinPlan plan = Stm32RawBinPlan.explicit(
                spec.exactPart(), spec.flashBase(), bytes.length, selection, ParserLimits.defaults());
            ByteArrayProvider provider = new ByteArrayProvider(spec.exactPart() + ".bin", bytes);

            Locale origLocale = Locale.getDefault();
            TimeZone origTz = TimeZone.getDefault();
            try {
                Locale.setDefault(Locale.forLanguageTag("tr-TR"));
                TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tehran"));
                Program guiProgram = createRawProgram(spec.exactPart(), GUI_CONSUMER);
                Stm32RawBinImporter.importInto(guiProgram, provider, plan, selection, TaskMonitor.DUMMY);

                Locale.setDefault(Locale.JAPAN);
                TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Auckland"));
                Program headlessProgram = createRawProgram(spec.exactPart(), HEADLESS_CONSUMER);
                Stm32RawBinImporter.importInto(headlessProgram, provider, plan, selection, TaskMonitor.DUMMY);

                try {
                    GhidraProgramEquivalenceAssertor.assertProgramEquivalence(guiProgram, headlessProgram);
                    GhidraProgramEquivalenceAssertor.assertWorkspaceSnapshotEquivalence(guiProgram, headlessProgram);
                }
                finally {
                    guiProgram.release(GUI_CONSUMER);
                    headlessProgram.release(HEADLESS_CONSUMER);
                }
            }
            finally {
                Locale.setDefault(origLocale);
                TimeZone.setDefault(origTz);
            }
        }
    }

    @Test
    void testAllStm32IntelHexGuiAndHeadlessEquivalence() throws Exception {
        IntelHexLoader loader = new IntelHexLoader();
        for (Stm32PartSpec spec : REPRESENTATIVE_PARTS) {
            byte[] bytes = fixture(spec.folder(), spec.exactPart() + ".hex");
            ByteArrayProvider provider = new ByteArrayProvider(spec.exactPart() + ".hex", bytes);
            LoadSpec loadSpec = new LoadSpec(loader, 0,
                new LanguageCompilerSpecPair(new LanguageID("ARM:LE:32:Cortex"), new CompilerSpecID("default")), false);
            List<Option> guiOpts = loader.getDefaultOptions(provider, loadSpec, null, false, false);
            List<Option> headlessOpts = loader.getDefaultOptions(provider, loadSpec, null, false, false);

            runLoaderEquivalence(loader, provider, loadSpec, guiOpts, headlessOpts);
        }
    }

    @Test
    void testAllStm32ElfGuiAndHeadlessEquivalence() throws Exception {
        ElfLoader loader = new ElfLoader();
        for (Stm32PartSpec spec : REPRESENTATIVE_PARTS) {
            byte[] bytes = fixture(spec.folder(), spec.exactPart() + ".elf");
            ByteArrayProvider provider = new ByteArrayProvider(spec.exactPart() + ".elf", bytes);
            Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
            assertFalse(specs.isEmpty(), "Specs must not be empty for ELF " + spec.exactPart());
            LoadSpec loadSpec = specs.iterator().next();
            List<Option> guiOpts = loader.getDefaultOptions(provider, loadSpec, null, false, false);
            List<Option> headlessOpts = loader.getDefaultOptions(provider, loadSpec, null, false, false);

            runLoaderEquivalence(loader, provider, loadSpec, guiOpts, headlessOpts);
        }
    }

    @Test
    void testStm32MpDeviceTreePlanGuiAndHeadlessEquivalence() throws Exception {
        byte[] bytes = fixture("stm32mp", "stm32mp157c-minimal.dts");
        String dts = new String(bytes, StandardCharsets.UTF_8);

        Locale origLocale = Locale.getDefault();
        TimeZone origTz = TimeZone.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tehran"));
            Stm32MpDeviceTreePlan guiPlan = Stm32MpDeviceTreeParser.parse(
                "STM32MP157C", dts, ParserLimits.defaults(), CancellationToken.none());

            Locale.setDefault(Locale.JAPAN);
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Auckland"));
            Stm32MpDeviceTreePlan headlessPlan = Stm32MpDeviceTreeParser.parse(
                "STM32MP157C", dts, ParserLimits.defaults(), CancellationToken.none());

            assertEquals(guiPlan, headlessPlan, "DTS plan must match bit-for-bit across locales");
            assertEquals(guiPlan.remoteProcNodes(), headlessPlan.remoteProcNodes());
            assertEquals(guiPlan.mailboxControllers(), headlessPlan.mailboxControllers());
            assertEquals(guiPlan.semaphoreControllers(), headlessPlan.semaphoreControllers());
            assertEquals(guiPlan.reservedMemoryNodes(), headlessPlan.reservedMemoryNodes());
            assertEquals(guiPlan.confidence(), headlessPlan.confidence());
            assertEquals(guiPlan.evidence(), headlessPlan.evidence());
            assertTrue(guiPlan.remoteProcNodes().size() >= 1);
        }
        finally {
            Locale.setDefault(origLocale);
            TimeZone.setDefault(origTz);
        }
    }

    private void runLoaderEquivalence(
            Loader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> guiOpts,
            List<Option> headlessOpts) throws Exception {
        Locale origLocale = Locale.getDefault();
        TimeZone origTz = TimeZone.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tehran"));
            Program guiProgram = loadProgram(loader, provider, spec, guiOpts, GUI_CONSUMER);

            Locale.setDefault(Locale.JAPAN);
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Auckland"));
            Program headlessProgram = loadProgram(loader, provider, spec, headlessOpts, HEADLESS_CONSUMER);

            try {
                GhidraProgramEquivalenceAssertor.assertProgramEquivalence(guiProgram, headlessProgram);
                GhidraProgramEquivalenceAssertor.assertWorkspaceSnapshotEquivalence(guiProgram, headlessProgram);
            }
            finally {
                guiProgram.release(GUI_CONSUMER);
                headlessProgram.release(HEADLESS_CONSUMER);
            }
        }
        finally {
            Locale.setDefault(origLocale);
            TimeZone.setDefault(origTz);
        }
    }

    private static Program createRawProgram(String name, Object consumer) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("ARM:LE:32:Cortex"));
        return new ProgramDB(name, language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), consumer);
    }

    private static Program loadProgram(
            Loader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> options,
            Object consumer) throws Exception {
        ImporterSettings settings = new ImporterSettings(
            provider, provider.getName(), null, "/",
            false, spec, options, consumer, new MessageLog(), TaskMonitor.DUMMY);
        LoadResults<?> results = loader.load(settings);
        Program[] captured = new Program[1];
        results.getPrimary().apply(domainObject -> captured[0] = (Program) domainObject);
        return captured[0];
    }

    private static byte[] fixture(String folder, String filename) throws IOException {
        String path = "/fixtures/" + folder + "/" + filename;
        try (InputStream input = Stm32WorkflowEquivalenceTest.class.getResourceAsStream(path)) {
            assertNotNull(input, "Missing fixture: " + path);
            return input.readAllBytes();
        }
    }
}
