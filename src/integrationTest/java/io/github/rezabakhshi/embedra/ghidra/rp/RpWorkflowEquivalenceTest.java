package io.github.rezabakhshi.embedra.ghidra.rp;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.ghidra.equivalence.GhidraProgramEquivalenceAssertor;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RpWorkflowEquivalenceTest {

    private static final Object GUI_CONSUMER = new Object();

    private static final Object HEADLESS_CONSUMER = new Object();

    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                    new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),
                    configuration);
        }
    }

    @Test
    void testRp2040GuiAndHeadlessEquivalence() throws Exception {
        assertEquivalenceForFixture("rp/rp2040-pico-blinky.uf2", null);
    }

    @Test
    void testRp2350ArmGuiAndHeadlessEquivalence() throws Exception {
        assertEquivalenceForFixture("rp/rp2350-arm-pico2.uf2", null);
    }

    @Test
    void testRp2350RiscvGuiAndHeadlessEquivalence() throws Exception {
        assertEquivalenceForFixture("rp/rp2350-riscv-pico2.uf2", null);
    }

    @Test
    void testRp2040Boot2RawBinaryGuiAndHeadlessEquivalence() throws Exception {
        assertEquivalenceForFixture("rp/rp2040-boot2-xip.bin", null);
    }

    @Test
    void testRp2354StackedFlashRawBinaryGuiAndHeadlessEquivalence() throws Exception {
        assertEquivalenceForFixture("rp/rp2354-stacked-flash.bin", "RP2354A");
    }

    @Test
    void testRp2040DualCoreElfGuiAndHeadlessEquivalence() throws Exception {
        assertElfEquivalenceForFixture("rp/rp2040-freestanding-dualcore.elf");
    }

    @Test
    void testRp2350ArmTrustZoneElfGuiAndHeadlessEquivalence() throws Exception {
        assertElfEquivalenceForFixture("rp/rp2350-arm-trustzone.elf");
    }

    @Test
    void testRp2350RiscvTrapElfGuiAndHeadlessEquivalence() throws Exception {
        assertElfEquivalenceForFixture("rp/rp2350-riscv-trap.elf");
    }

    private void assertEquivalenceForFixture(String fixtureRelPath, String targetPartOverride) throws Exception {
        byte[] input = fixture(fixtureRelPath);
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider(fixtureRelPath, input);
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertTrue(!specs.isEmpty(), "Should find load specs for " + fixtureRelPath);
        LoadSpec spec = specs.iterator().next();

        List<Option> guiOpts = loader.getDefaultOptions(provider, spec, null, false, false);
        List<Option> headlessOpts = loader.getDefaultOptions(provider, spec, null, false, false);

        if (targetPartOverride != null) {
            guiOpts.stream()
                    .filter(o -> RpFirmwareLoader.TARGET_PART_OPTION.equals(o.getName()))
                    .findFirst().orElseThrow().setValue(targetPartOverride);
            headlessOpts.stream()
                    .filter(o -> RpFirmwareLoader.TARGET_PART_OPTION.equals(o.getName()))
                    .findFirst().orElseThrow().setValue(targetPartOverride);
        }

        runEquivalenceAssertion(loader, provider, spec, guiOpts, headlessOpts);
    }

    private void assertElfEquivalenceForFixture(String fixtureRelPath) throws Exception {
        byte[] input = fixture(fixtureRelPath);
        ElfLoader loader = new ElfLoader();
        ByteArrayProvider provider = new ByteArrayProvider(fixtureRelPath, input);
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertTrue(!specs.isEmpty(), "Should find load specs for ELF " + fixtureRelPath);
        LoadSpec spec = specs.iterator().next();

        List<Option> guiOpts = loader.getDefaultOptions(provider, spec, null, false, false);
        List<Option> headlessOpts = loader.getDefaultOptions(provider, spec, null, false, false);

        runEquivalenceAssertion(loader, provider, spec, guiOpts, headlessOpts);
    }

    private void runEquivalenceAssertion(
            Loader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> guiOpts,
            List<Option> headlessOpts) throws Exception {
        Locale origLocale = Locale.getDefault();
        TimeZone origTz = TimeZone.getDefault();

        try {
            // 1. Simulate GUI Interactive Import
            Locale.setDefault(Locale.US);
            TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
            Program guiProgram = loadProgram(loader, provider, spec, guiOpts, GUI_CONSUMER);

            // 2. Simulate Headless Batch Import
            Locale.setDefault(Locale.JAPAN);
            TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tokyo"));
            Program headlessProgram = loadProgram(loader, provider, spec, headlessOpts, HEADLESS_CONSUMER);

            try {
                // Assert bit-for-bit and symbol-for-symbol equivalence
                GhidraProgramEquivalenceAssertor.assertProgramEquivalence(guiProgram, headlessProgram);
                GhidraProgramEquivalenceAssertor.assertWorkspaceSnapshotEquivalence(guiProgram, headlessProgram);
            } finally {
                guiProgram.release(GUI_CONSUMER);
                headlessProgram.release(HEADLESS_CONSUMER);
            }
        } finally {
            Locale.setDefault(origLocale);
            TimeZone.setDefault(origTz);
        }
    }

    private static Program loadProgram(
            Loader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> options,
            Object consumer) throws Exception {
        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, options, consumer, new MessageLog(), TaskMonitor.DUMMY);
        LoadResults<? extends DomainObject> results = loader.load(settings);
        final Program[] progRef = new Program[1];
        results.getPrimary().apply(d -> progRef[0] = (Program) d);
        return progRef[0];
    }

    private static byte[] fixture(String path) throws IOException {
        try (InputStream input = RpWorkflowEquivalenceTest.class.getResourceAsStream("/fixtures/" + path)) {
            assertNotNull(input, "missing fixture " + path);
            return input.readAllBytes();
        }
    }
}
