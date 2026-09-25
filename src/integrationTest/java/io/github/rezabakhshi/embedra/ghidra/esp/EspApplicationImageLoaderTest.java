package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.Option;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.ByteMemBufferImpl;
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
        assertEquals("Xtensa:LE:32:esp32s3",
            spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());
        assertEquals("default",
            spec.getLanguageCompilerSpec().getCompilerSpecID().getIdAsString());
        assertTrue(spec.isPreferred());
    }

    @Test
    void detectsAndImportsEspFamiliesWithIndependentTargets()
            throws Exception {
        for (String deviceId : List.of("esp32", "esp32s2", "esp32c3")) {
            EspApplicationImageLoader loader = new EspApplicationImageLoader();
            ByteArrayProvider provider = new ByteArrayProvider("neutral.dat",
                familyFixture(deviceId));
            LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
            String expectedLanguage = deviceId.equals("esp32c3")
                ? "RISCV:LE:32:default" : "Xtensa:LE:32:default";
            assertEquals(expectedLanguage,
                spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());
            assertEquals(deviceId.equals("esp32c3") ? "gcc" : "default",
                spec.getLanguageCompilerSpec().getCompilerSpecID().getIdAsString());
            ImporterSettings settings = new ImporterSettings(provider,
                deviceId + ".bin", null, "/", false, spec,
                loader.getDefaultOptions(provider, spec, null, false, false),
                new Object(), new MessageLog(), TaskMonitor.DUMMY);

            try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
                results.getPrimary().apply(domainObject -> {
                    Program program = (Program) domainObject;
                    assertEquals(expectedLanguage,
                        program.getLanguageID().getIdAsString());
                    assertEquals(3, java.util.Arrays.stream(program.getMemory().getBlocks())
                        .filter(block -> block.getName().startsWith("esp_segment_"))
                        .count());
                    assertEquals("target." + deviceId, program.getOptions(
                        EspApplicationImageLoader.ESP_ENRICHMENT_OPTIONS).getString(
                            "Target Provider", ""));
                    assertEquals(deviceId.toUpperCase() + "_ENRICHMENT_DISABLED",
                        program.getOptions(EspApplicationImageLoader.ESP_ENRICHMENT_OPTIONS)
                            .getString("Diagnostic Code", ""));
                });
            }
        }
    }

    @Test
    void appliesMatchingEspFamilyPacksWhenSelected() throws Exception {
        for (String deviceId : List.of("esp32", "esp32s2", "esp32c3")) {
            String displayName = switch (deviceId) {
                case "esp32" -> "ESP32";
                case "esp32s2" -> "ESP32-S2";
                case "esp32c3" -> "ESP32-C3";
                default -> throw new AssertionError(deviceId);
            };
            EspApplicationImageLoader loader = new EspApplicationImageLoader();
            ByteArrayProvider provider = new ByteArrayProvider("neutral.dat",
                familyFixture(deviceId));
            LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
            List<Option> options = loader.getDefaultOptions(provider, spec, null,
                false, false);
            options.stream().filter(option -> option.getName().equals(
                EspApplicationImageLoader.APPLY_ESP32S3_PACKS_OPTION)).findFirst()
                .orElseThrow().setValue(Boolean.TRUE);
            ImporterSettings settings = new ImporterSettings(provider,
                deviceId + ".bin", null, "/", false, spec, options, new Object(),
                new MessageLog(), TaskMonitor.DUMMY);

            try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
                results.getPrimary().apply(domainObject -> {
                    Program program = (Program) domainObject;
                    assertEquals("espressif." + deviceId + ".rom", program.getOptions(
                        "Embedra " + displayName + " Packs").getString(
                            "ROM Pack ID", ""));
                    assertEquals("espressif." + deviceId + ".svd", program.getOptions(
                        "Embedra " + displayName + " SVD").getString("Pack ID", ""));
                    assertTrue(program.getOptions(
                        EspApplicationImageLoader.ESP_ENRICHMENT_OPTIONS).getBoolean(
                            "Selected", false));
                    assertEquals(deviceId.toUpperCase() + "_ENRICHMENT_APPLIED",
                        program.getOptions(EspApplicationImageLoader.ESP_ENRICHMENT_OPTIONS)
                            .getString("Diagnostic Code", ""));
                });
            }
        }
    }

    @Test
    void exposesConservativeOptInForBundledRegisterAndRomEnrichment()
            throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("firmware.bin",
            fixture("esp32s3-freestanding-minimal.bin"));
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();

        List<Option> options = loader.getDefaultOptions(provider, spec, null,
            false, false);

        Option enrichment = options.stream().filter(option -> option.getName().equals(
            EspApplicationImageLoader.APPLY_ESP32S3_PACKS_OPTION)).findFirst().orElseThrow();
        assertEquals(Boolean.FALSE, enrichment.getValue());
    }

    @Test
    void defaultImportRecordsDisabledEnrichmentAndExplainsMissingAnalysis()
            throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("firmware.bin",
            fixture("esp32s3-freestanding-minimal.bin"));
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        MessageLog log = new MessageLog();
        ImporterSettings settings = new ImporterSettings(provider, "firmware.bin",
            null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false),
            new Object(), log, TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                assertEquals("Xtensa:LE:32:esp32s3",
                    program.getLanguageID().getIdAsString());
                var status = program.getOptions(EspApplicationImageLoader.ENRICHMENT_OPTIONS);
                assertFalse(status.getBoolean("Selected", true));
                assertEquals(EspApplicationImageLoader.ENRICHMENT_DISABLED_CODE,
                    status.getString("Diagnostic Code", ""));
                assertFalse(new EmbedraEsp32S3CryptoAnalyzer().canAnalyze(program));
            });
        }
        assertTrue(log.toString().contains(EspApplicationImageLoader.ENRICHMENT_DISABLED_CODE));
    }

    @Test
    void appliesBundledSvdRomAndPeripheralPacksOnlyWhenSelected() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("firmware.bin",
            fixture("esp32s3-freestanding-minimal.bin"));
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        List<Option> options = loader.getDefaultOptions(provider, spec, null,
            false, false);
        options.stream().filter(option -> option.getName().equals(
            EspApplicationImageLoader.APPLY_ESP32S3_PACKS_OPTION)).findFirst()
            .orElseThrow().setValue(Boolean.TRUE);
        Object consumer = new Object();
        ImporterSettings settings = new ImporterSettings(provider, "firmware.bin",
            null, "/", false, spec, options, consumer, new MessageLog(),
            TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                assertEquals("ets_printf", program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(0x4000_05d0L)).getName());
                assertNotNull(program.getListing().getDefinedDataAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(0x6003_a040L)));
                assertEquals("espressif.esp32s3.svd", program.getOptions(
                    "Embedra ESP32-S3 SVD").getString("Pack ID", ""));
                assertTrue(program.getOptions(EspApplicationImageLoader.ENRICHMENT_OPTIONS)
                    .getBoolean("Selected", false));
                assertTrue(new EmbedraEsp32S3CryptoAnalyzer().canAnalyze(program));
            });
        }
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
    void fullFlashImportLogDoesNotExposeInputFilename() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("neutral",
            fullFlashFixture("default-factory.bin"));
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        MessageLog log = new MessageLog();
        ImporterSettings settings = new ImporterSettings(provider,
            "esp32s3_ctf_dump_4MB.bin", null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false),
            new Object(), log, TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            assertEquals(2, results.size());
        }
        assertFalse(log.toString().contains("esp32s3_ctf_dump_4MB"));
        assertTrue(log.toString().contains(EspApplicationImageLoader.ENRICHMENT_DISABLED_CODE));
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
        var workspace = io.github.rezabakhshi.embedra.formats.esp
            .EspFullFlashWorkspacePlanner.plan(flash,
                io.github.rezabakhshi.embedra.core.ParserLimits.defaults(),
                io.github.rezabakhshi.embedra.core.CancellationToken.none());
        assertEquals(5, workspace.dataPartitions().size());
        var app = workspace.executables().stream()
            .filter(executable -> executable.role() !=
                io.github.rezabakhshi.embedra.formats.esp.EspExecutableRole.BOOTLOADER)
            .findFirst().orElseThrow();
        var boot = workspace.executables().stream()
            .filter(executable -> executable.role() ==
                io.github.rezabakhshi.embedra.formats.esp.EspExecutableRole.BOOTLOADER)
            .findFirst().orElseThrow();
        assertEquals(6, app.image().segments().size());
        assertEquals(3, boot.image().segments().size());
        var code = app.image().segments().stream()
            .filter(segment -> segment.loadAddress() == 0x4200_0020L)
            .findFirst().orElseThrow();
        assertEquals(0x420d421cL, code.targetRange().endExclusive());
        long[] observedAddresses = {0x420bdf4fL, 0x420bc6c4L, 0x420bc508L};
        byte[][] observedBytes = {
            {0x50, (byte) 0x88, 0x72},
            {(byte) 0x90, (byte) 0x88, 0x62},
            {(byte) 0x90, (byte) 0x98, 0x72}
        };
        for (int instruction = 0; instruction < observedAddresses.length; instruction++) {
            long sourceOffset = app.flashRange().offset()
                + code.dataSourceRange().offset()
                + observedAddresses[instruction] - code.loadAddress();
            for (int byteIndex = 0; byteIndex < 3; byteIndex++) {
                assertEquals(observedBytes[instruction][byteIndex] & 0xff,
                    flash[Math.toIntExact(sourceOffset + byteIndex)] & 0xff);
            }
        }
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("untrusted-name.dat", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        Object consumer = new Object();
        List<Option> options = loader.getDefaultOptions(provider, spec, null,
            false, false);
        options.stream().filter(option -> option.getName().equals(
            EspApplicationImageLoader.APPLY_ESP32S3_PACKS_OPTION)).findFirst()
            .orElseThrow().setValue(Boolean.TRUE);
        MessageLog log = new MessageLog();
        ImporterSettings settings = new ImporterSettings(provider,
            "restricted-local", null, "/", false, spec,
            options, consumer, log, TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            assertEquals(2, results.size());
            List<String> names = new java.util.ArrayList<>();
            results.forEach(loaded -> names.add(loaded.getName()));
            assertEquals(List.of("restricted-local_app0",
                "restricted-local_bootloader"), names);
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                assertNotNull(program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(0x4000_05d0L)));
                assertEquals("ets_printf", program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(0x4000_05d0L)).getName());
                assertTrue(program.getListing().getDefinedDataAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(0x6003_a040L)).getDataType().getName()
                    .contains("AES_MODE"));
                assertEquals("espressif.esp32s3.svd", program.getOptions(
                    "Embedra ESP32-S3 SVD").getString("Pack ID", ""));
                assertTrue(new EmbedraEsp32S3CryptoAnalyzer().canAnalyze(program));
                var at = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(0x420bdf4fL);
                assertEquals(0x50, assertDoesNotThrow(
                    () -> program.getMemory().getByte(at)) & 0xff);
                assertEquals(0x88, assertDoesNotThrow(
                    () -> program.getMemory().getByte(at.add(1))) & 0xff);
                assertEquals(0x72, assertDoesNotThrow(
                    () -> program.getMemory().getByte(at.add(2))) & 0xff);
                assertRestrictedInstruction(program, 0x420bdf4fL,
                    new byte[] {0x50, (byte) 0x88, 0x72}, "salt");
                assertRestrictedInstruction(program, 0x420bc6c4L,
                    new byte[] {(byte) 0x90, (byte) 0x88, 0x62}, "saltu");
                assertRestrictedInstruction(program, 0x420bc508L,
                    new byte[] {(byte) 0x90, (byte) 0x98, 0x72}, "salt");
            });
        }
        assertTrue(log.toString().contains(EspApplicationImageLoader.ENRICHMENT_APPLIED_CODE));
    }

    private static void assertRestrictedInstruction(Program program, long offset,
            byte[] expected, String mnemonic) {
        var address = program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(offset);
        for (int index = 0; index < expected.length; index++) {
            int position = index;
            assertEquals(expected[index] & 0xff, assertDoesNotThrow(
                () -> program.getMemory().getByte(address.add(position))) & 0xff);
        }
        var language = program.getLanguage();
        var instruction = assertDoesNotThrow(() -> language.parse(
            new ByteMemBufferImpl(address, expected, false),
            new ProcessorContextImpl(language), false));
        assertEquals(3, instruction.getLength());
        assertEquals(mnemonic, assertDoesNotThrow(() -> instruction.getMnemonic(
            new ghidra.app.util.PseudoInstruction(address, instruction,
                new ByteMemBufferImpl(address, expected, false),
                new ProcessorContextImpl(language)))).toLowerCase());
    }

    @Test
    void restrictedDumpDefaultImportLeavesEnrichmentUnavailable() throws Exception {
        Path dump = Path.of(System.getProperty("embedra.projectDir"),
            "esp32s3_ctf_dump_4MB.bin");
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.isRegularFile(dump),
            "restricted local fixture is intentionally absent from public CI");
        byte[] flash = Files.readAllBytes(dump);
        assertEquals(RESTRICTED_DUMP_SHA256, HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(flash)));
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("local-capture", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        MessageLog log = new MessageLog();
        ImporterSettings settings = new ImporterSettings(provider, "local-capture",
            null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false),
            new Object(), log, TaskMonitor.DUMMY);
        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            assertEquals(2, results.size());
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                assertEquals(6, program.getMemory().getBlocks().length);
                assertFalse(program.getOptions(EspApplicationImageLoader.ENRICHMENT_OPTIONS)
                    .getBoolean("Selected", true));
                assertFalse(new EmbedraEsp32S3CryptoAnalyzer().canAnalyze(program));
            });
        }
        assertTrue(log.toString().contains(EspApplicationImageLoader.ENRICHMENT_DISABLED_CODE));
    }

    @Test
    void importPersistsValidatedAppDescriptionEvidenceForVersionGating()
            throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("firmware.bin", fixture(
            "esp32s3-freestanding-minimal.bin"));
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        ImporterSettings settings = new ImporterSettings(provider, "firmware.bin",
            null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false),
            new Object(), new MessageLog(), TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;
                var options = program.getOptions(EmbedraEsp32S3FunctionIdAnalyzer
                    .APP_DESCRIPTION_OPTIONS);
                assertEquals("fixture-no-idf-runtime", options.getString(
                    EmbedraEsp32S3FunctionIdAnalyzer.APP_DESCRIPTION_IDF_VERSION_KEY, ""));
                assertEquals("embedra_t008_fixture",
                    options.getString("Project Name", ""));
                assertEquals("1.0.0", options.getString("App Version", ""));
            });
        }
    }

    @Test
    void everyFullFlashProgramRecordsOnlyValidatedDescriptorEvidence() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        byte[] flash = fullFlashFixture("default-factory.bin");
        ByteArrayProvider provider = new ByteArrayProvider("flash.raw", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        Object consumer = new Object();
        ImporterSettings settings = new ImporterSettings(provider, "flash.raw",
            null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false), consumer,
            new MessageLog(), TaskMonitor.DUMMY);

        java.util.Set<String> versions = new java.util.HashSet<>();
        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            assertEquals(2, results.size());
            for (var loaded : results) {
                loaded.apply(domainObject -> {
                    Program program = (Program) domainObject;
                    String version = program.getOptions(EmbedraEsp32S3FunctionIdAnalyzer
                        .APP_DESCRIPTION_OPTIONS).getString(
                            EmbedraEsp32S3FunctionIdAnalyzer
                                .APP_DESCRIPTION_IDF_VERSION_KEY, "");
                    // The default-factory fixture overlays the same validated golden
                    // image (containing esp_app_desc with this literal version string)
                    // in both executable regions; a region without a valid descriptor
                    // would record nothing rather than an invented value.
                    assertEquals("fixture-no-idf-runtime", version);
                    versions.add(version);
                });
            }
        }
        assertEquals(1, versions.size());
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

    private static byte[] familyFixture(String deviceId) throws IOException {
        String resource = "/fixtures/" + deviceId + "/" + deviceId
            + "-freestanding-minimal.bin";
        try (InputStream input = EspApplicationImageLoaderTest.class
                .getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("Missing fixture " + resource);
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
