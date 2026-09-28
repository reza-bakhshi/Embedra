package io.github.rezabakhshi.embedra.ghidra.esp8266;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.ghidra.esp.EspApplicationImageLoader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class Esp8266LegacyImageLoaderTest {
    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getenv("GHIDRA_INSTALL_DIR"))), configuration);
        }
    }

    @Test
    void loadsVersion1AsRamOnlyWithUnencodedExactIdentity() throws Exception {
        Esp8266LegacyImageLoader loader = new Esp8266LegacyImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("neutral.dat",
            fixture("esp8266/esp8266-freestanding-v1-0x00000.bin"));
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();

        assertEquals("Xtensa:LE:32:default",
            spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());
        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec,
                loader.getDefaultOptions(provider, spec, null, false, false))) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                assertEquals(2, program.getMemory().getBlocks().length);
                var options = program.getOptions(
                    Esp8266LegacyImageMapper.PROGRAM_OPTIONS);
                assertEquals("VERSION_1", options.getString("Image Version", ""));
                assertEquals("NOT_ENCODED_ESP8266EX_OR_ESP8285",
                    options.getString("Exact Silicon Identity", ""));
                assertFalse(options.contains("Explicit Flash Base"));
            });
        }
    }

    @Test
    void loadsVersion2IromUsingTheExplicitFlashBase() throws Exception {
        Esp8266LegacyImageLoader loader = new Esp8266LegacyImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("neutral.dat",
            fixture("esp8266/esp8266-freestanding-v2-0x01000.bin"));
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        List<Option> options = loader.getDefaultOptions(provider, spec, null,
            false, false);

        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec,
                options)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                assertEquals(3, program.getMemory().getBlocks().length);
                assertTrue(program.getMemory().contains(program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(0x4020_1010L)));
                assertEquals(0x1000, program.getOptions(
                    Esp8266LegacyImageMapper.PROGRAM_OPTIONS).getLong(
                        "Explicit Flash Base", -1));
            });
        }
    }

    @Test
    void keepsModernEspAndLegacyEsp8266LoadersSeparated() throws Exception {
        Esp8266LegacyImageLoader legacy = new Esp8266LegacyImageLoader();
        EspApplicationImageLoader modern = new EspApplicationImageLoader();
        byte[] modernBytes = fixture("esp32s3/esp32s3-freestanding-minimal.bin");
        byte[] legacyBytes = fixture("esp8266/esp8266-freestanding-v2-0x01000.bin");

        assertTrue(legacy.findSupportedLoadSpecs(
            new ByteArrayProvider("modern.bin", modernBytes)).isEmpty());
        assertTrue(modern.findSupportedLoadSpecs(
            new ByteArrayProvider("legacy.bin", legacyBytes)).isEmpty());
    }

    @Test
    void validatesExplicitFlashBaseOption() throws Exception {
        Esp8266LegacyImageLoader loader = new Esp8266LegacyImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("neutral.dat",
            fixture("esp8266/esp8266-freestanding-v2-0x01000.bin"));
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        List<Option> options = loader.getDefaultOptions(provider, spec, null,
            false, false);
        options.stream().filter(option -> option.getName().equals(
            Esp8266LegacyImageLoader.FLASH_BASE_OPTION)).findFirst().orElseThrow()
                .setValue(0x1001L);

        assertTrue(loader.validateOptions(provider, spec, options, null)
            .contains("4 KiB aligned"));
    }

    private static LoadResults<? extends DomainObject> load(
            Esp8266LegacyImageLoader loader, ByteArrayProvider provider, LoadSpec spec,
            List<Option> options) throws Exception {
        ImporterSettings settings = new ImporterSettings(provider, "legacy.bin", null,
            "/", false, spec, options, new Object(), new MessageLog(), TaskMonitor.DUMMY);
        return loader.load(settings);
    }

    private static byte[] fixture(String path) throws IOException {
        try (InputStream input = Esp8266LegacyImageLoaderTest.class
                .getResourceAsStream("/fixtures/" + path)) {
            assertTrue(input != null, "missing fixture " + path);
            return input.readAllBytes();
        }
    }
}
