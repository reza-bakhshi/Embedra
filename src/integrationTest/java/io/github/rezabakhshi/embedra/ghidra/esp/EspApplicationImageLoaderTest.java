package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
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
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class EspApplicationImageLoaderTest {
    private static final String RESTRICTED_DUMP_SHA256 =
        "837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de";

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

    @Test
    void detectsValidatedEsp32S3ImageByBytesNotFilename() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(
            new ByteArrayProvider("misleading.txt", fixture(
                "esp32s3-freestanding-minimal.bin")));

        assertEquals("Embedra ESP Application Image", loader.getName());
        assertEquals(1, specs.size());
        LoadSpec spec = specs.iterator().next();
        assertEquals("Xtensa:LE:32:default",
            spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());
        assertEquals("default",
            spec.getLanguageCompilerSpec().getCompilerSpecID().getIdAsString());
        assertTrue(spec.isPreferred());
    }

    @Test
    void rejectsFilenameMatchesMalformedImagesAndWrongChip() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();

        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("firmware.bin",
            new byte[] {0x45, 0x4d, 0x42, 0x52})).isEmpty());
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("firmware.bin",
            fixture("malformed/malformed-checksum.bin"))).isEmpty());
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("firmware.bin",
            fixture("malformed/malformed-wrong-chip.bin"))).isEmpty());
    }

    @Test
    void detectsFullFlashByContentAndLoadsIndependentPrograms() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        byte[] flash = fullFlashFixture("default-factory.bin");
        ByteArrayProvider provider = new ByteArrayProvider("unknown.capture", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        Object consumer = new Object();
        ImporterSettings settings = new ImporterSettings(provider, "unknown.capture",
            null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false), consumer,
            new MessageLog(), TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            assertEquals(2, results.size());
            List<String> names = new java.util.ArrayList<>();
            for (var loaded : results) {
                names.add(loaded.getName());
                loaded.apply(domainObject -> {
                    Program program = (Program) domainObject;
                    assertEquals(3, program.getMemory().getBlocks().length);
                    assertTrue(program.getSymbolTable().getExternalEntryPointIterator()
                        .hasNext());
                    var provenance = program.getOptions(
                        "Embedra Full Flash Provenance");
                    assertEquals(0x8000,
                        provenance.getLong("Partition Table Offset", -1));
                    assertEquals(432,
                        provenance.getLong("Executable Flash Length", -1));
                    assertEquals("45cac3c72a7c4215cceef05e7b750def8372304586d9d2e022969c48e4963650",
                        provenance.getString("Source SHA-256", ""));
                });
            }
            assertEquals(List.of("unknown_factory", "unknown_bootloader"), names);
        }
    }

    @Test
    void loadsBootloaderAndBothOtaSlotsButNotEncryptedDataAsPrograms()
            throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        byte[] flash = fullFlashFixture("ota-custom-encrypted.bin");
        ByteArrayProvider provider = new ByteArrayProvider("ota.raw", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        Object consumer = new Object();
        ImporterSettings settings = new ImporterSettings(provider, "ota.raw", null,
            "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false), consumer,
            new MessageLog(), TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            assertEquals(3, results.size());
            List<String> names = new java.util.ArrayList<>();
            results.forEach(loaded -> names.add(loaded.getName()));
            assertEquals(List.of("ota_ota_0", "ota_ota_1", "ota_bootloader"),
                names);
            assertFalse(names.stream().anyMatch(name -> name.contains("assets")));
        }
    }

    @Test
    void rejectsFullFlashWithInvalidPartitionMd5() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();

        assertFalse(loader.findSupportedLoadSpecs(new ByteArrayProvider("valid-name.bin",
            fullFlashFixture("invalid-partition-md5.bin"))).iterator().hasNext());
    }

    @Test
    void importsRestrictedRealDumpWithoutCreatingProgramForErasedOtaSlot()
            throws Exception {
        Path dump = Path.of(System.getProperty("embedra.projectDir"),
            "esp32s3_ctf_dump_4MB.bin");
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.isRegularFile(dump),
            "restricted local fixture is intentionally absent from public CI");
        byte[] flash = Files.readAllBytes(dump);
        assertEquals(RESTRICTED_DUMP_SHA256, HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(flash)));
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("untrusted-name.dat", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        Object consumer = new Object();
        ImporterSettings settings = new ImporterSettings(provider,
            "esp32s3_ctf_dump_4MB.bin", null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false), consumer,
            new MessageLog(), TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            assertEquals(2, results.size());
            List<String> names = new java.util.ArrayList<>();
            results.forEach(loaded -> names.add(loaded.getName()));
            assertEquals(List.of("esp32s3_ctf_dump_4MB_app0",
                "esp32s3_ctf_dump_4MB_bootloader"), names);
        }
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream input = EspApplicationImageLoaderTest.class.getResourceAsStream(
                "/fixtures/esp32s3/" + name)) {
            if (input == null) {
                throw new IOException("Missing fixture " + name);
            }
            return input.readAllBytes();
        }
    }

    private static byte[] fullFlashFixture(String name) throws IOException {
        try (InputStream input = EspApplicationImageLoaderTest.class.getResourceAsStream(
                "/fixtures/esp32s3/full-flash/" + name)) {
            if (input == null) {
                throw new IOException("Missing full-flash fixture " + name);
            }
            return input.readAllBytes();
        }
    }
}
