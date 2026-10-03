package io.github.rezabakhshi.embedra.ghidra.rp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RpFirmwareLoaderTest {

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
    void testLoadRp2040Uf2Image() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("blinky.uf2", fixture("rp/rp2040-pico-blinky.uf2"));

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty(), "Should support RP2040 UF2");
        LoadSpec spec = specs.iterator().next();
        assertEquals("ARM:LE:32:Cortex", spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());

        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);

        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec, options)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);
                assertTrue(program.getMemory().contains(baseAddr));

                // Verify entry point
                Address entryAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000141L);
                assertNotNull(program.getSymbolTable().getPrimarySymbol(entryAddr));
                assertEquals("entry", program.getSymbolTable().getPrimarySymbol(entryAddr).getName());

                // Verify options
                var progOptions = program.getOptions(RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY);
                assertEquals("RP2040", progOptions.getString("Series", ""));
                assertEquals("UF2", progOptions.getString("Container Format", ""));
                assertEquals("RP2040", progOptions.getString("Target Silicon Part", ""));
                assertEquals("0x20042000", progOptions.getString("Initial SP", ""));
                assertEquals("0x10000141", progOptions.getString("Reset Vector", ""));

                // Verify bookmarks
                Bookmark[] bms = program.getBookmarkManager().getBookmarks(baseAddr);
                assertTrue(bms.length > 0, "Should have bookmark at flash base");
            });
        }
    }

    @Test
    void testLoadRp2350ArmUf2Image() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("pico2_arm.uf2", fixture("rp/rp2350-arm-pico2.uf2"));

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty(), "Should support RP2350 ARM UF2");
        LoadSpec spec = specs.iterator().next();
        assertEquals("ARM:LE:32:v8-m", spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());

        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);

        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec, options)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);
                assertTrue(program.getMemory().contains(baseAddr));

                var progOptions = program.getOptions(RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY);
                assertEquals("RP2350", progOptions.getString("Series", ""));
                assertEquals("UF2", progOptions.getString("Container Format", ""));
                assertTrue(progOptions.getString("Architecture", "").contains("Cortex-M33"));
                assertEquals("Secure", progOptions.getString("Security Domain", ""));
                assertTrue(progOptions.getBoolean("IMAGE_DEF Present", false));
            });
        }
    }

    @Test
    void testLoadRp2350RiscvUf2Image() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("pico2_rv.uf2", fixture("rp/rp2350-riscv-pico2.uf2"));

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty(), "Should support RP2350 RISC-V UF2");
        LoadSpec spec = specs.iterator().next();
        assertEquals("RISCV:LE:32:default", spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());
        assertEquals("gcc", spec.getLanguageCompilerSpec().getCompilerSpecID().getIdAsString());

        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);

        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec, options)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);
                assertTrue(program.getMemory().contains(baseAddr));

                Address entryAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000100L);
                assertNotNull(program.getSymbolTable().getPrimarySymbol(entryAddr));
                assertEquals("entry", program.getSymbolTable().getPrimarySymbol(entryAddr).getName());

                var progOptions = program.getOptions(RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY);
                assertEquals("RP2350", progOptions.getString("Series", ""));
                assertTrue(progOptions.getString("Architecture", "").contains("Hazard3"));
            });
        }
    }

    @Test
    void testLoadRp2354StackedFlashRawBinary() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider(
                "stacked.bin", fixture("rp/rp2354-stacked-flash.bin"));

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty(), "Should support RP2354 raw binary");
        LoadSpec spec = specs.iterator().next();
        assertEquals("ARM:LE:32:v8-m", spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());

        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);
        options.stream()
                .filter(o -> RpFirmwareLoader.TARGET_PART_OPTION.equals(o.getName()))
                .findFirst()
                .orElseThrow()
                .setValue("RP2354A");

        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec, options)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);
                assertTrue(program.getMemory().contains(baseAddr));

                var progOptions = program.getOptions(RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY);
                assertEquals("RP2354", progOptions.getString("Series", ""));
                assertEquals("RP2354A", progOptions.getString("Target Silicon Part", ""));
                assertTrue(progOptions.getBoolean("Stacked Flash", false));
            });
        }
    }

    @Test
    void testLoadRp2040Boot2RawBinary() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider(
                "boot2.bin", fixture("rp/rp2040-boot2-xip.bin"));

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty(), "Should support RP2040 boot2 raw binary");
        LoadSpec spec = specs.iterator().next();
        assertEquals("ARM:LE:32:Cortex", spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());
    }

    @Test
    void testRejectsForeignAndMalformedInputs() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();

        // ESP32 image rejected
        byte[] espBytes = fixture("esp32s3/esp32s3-freestanding-minimal.bin");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("esp.bin", espBytes)).isEmpty());

        // Corrupted UF2 magic rejected
        byte[] corruptUf2 = fixture("rp/malformed/uf2-corrupted-magic.uf2");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("bad.uf2", corruptUf2)).isEmpty());

        // Option validation: unknown part rejected
        LoadSpec dummySpec = new LoadSpec(loader, 0,
                new ghidra.program.model.lang.LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default"), false);
        ByteArrayProvider dummyProv = new ByteArrayProvider("dummy.uf2", fixture("rp/rp2040-pico-blinky.uf2"));
        List<Option> opts = loader.getDefaultOptions(dummyProv, dummySpec, null, false, false);
        opts.stream()
                .filter(o -> RpFirmwareLoader.TARGET_PART_OPTION.equals(o.getName()))
                .findFirst()
                .orElseThrow()
                .setValue("RP9999");
        assertNotNull(loader.validateOptions(dummyProv, dummySpec, opts, null));
    }

    @Test
    void testLoaderInstantiationAndNonRpInputs() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        assertNotNull(loader.getName());
        ByteArrayProvider nonRp = new ByteArrayProvider("esp_image.bin",
                new byte[] { (byte) 0xe9, 0x03, 0x02, 0x2f, 0x10, (byte) 0xc7, 0x3c, 0x40 });
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(nonRp);
        assertTrue(specs.isEmpty(), "RP firmware loader must return empty LoadSpec list for non-RP input");
    }

    private static LoadResults<? extends DomainObject> load(
            RpFirmwareLoader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> options) throws Exception {
        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, options, new Object(), new MessageLog(), TaskMonitor.DUMMY);
        return loader.load(settings);
    }

    private static byte[] fixture(String path) throws IOException {
        try (InputStream input = RpFirmwareLoaderTest.class.getResourceAsStream("/fixtures/" + path)) {
            assertNotNull(input, "missing fixture " + path);
            return input.readAllBytes();
        }
    }
}
