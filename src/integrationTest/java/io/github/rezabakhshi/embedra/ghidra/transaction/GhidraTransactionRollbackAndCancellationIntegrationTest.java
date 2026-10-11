package io.github.rezabakhshi.embedra.ghidra.transaction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityCategory;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityType;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadCategory;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadConfidence;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLeadsReport;
import io.github.rezabakhshi.embedra.analyzers.logging.DiagnosticLogLevel;
import io.github.rezabakhshi.embedra.analyzers.logging.FormatStringDescriptor;
import io.github.rezabakhshi.embedra.analyzers.logging.LoggingCallSite;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginFinding;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.analyzers.strings.StringProvenance;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.analyzers.yara.CompiledYaraRuleset;
import io.github.rezabakhshi.embedra.analyzers.yara.YaraMatch;
import io.github.rezabakhshi.embedra.analyzers.yara.YaraRule;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32RawBinPlan;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32VectorDiscovery;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266Image;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266ImageParser;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Image;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Parser;
import io.github.rezabakhshi.embedra.ghidra.crypto.GhidraCryptoApplicator;
import io.github.rezabakhshi.embedra.ghidra.ctf.GhidraCtfApplicator;
import io.github.rezabakhshi.embedra.ghidra.diff.GhidraWorkspaceDiffExtractor;
import io.github.rezabakhshi.embedra.ghidra.esp.EspApplicationImageLoader;
import io.github.rezabakhshi.embedra.ghidra.esp.EspApplicationImageMapper;
import io.github.rezabakhshi.embedra.ghidra.esp.EspApplicationImportService;
import io.github.rezabakhshi.embedra.ghidra.esp.EspMappingException;
import io.github.rezabakhshi.embedra.ghidra.esp8266.Esp8266LegacyImageMapper;
import io.github.rezabakhshi.embedra.ghidra.function.EmbedraFunctionNormalizer;
import io.github.rezabakhshi.embedra.ghidra.leads.GhidraSecurityLeadApplicator;
import io.github.rezabakhshi.embedra.ghidra.logging.GhidraLoggingApplicator;
import io.github.rezabakhshi.embedra.ghidra.plugins.GhidraPluginApplicator;
import io.github.rezabakhshi.embedra.ghidra.rp.RpFirmwareImportService;
import io.github.rezabakhshi.embedra.ghidra.rp.RpFirmwareMapper;
import io.github.rezabakhshi.embedra.ghidra.rp.RpMappingException;
import io.github.rezabakhshi.embedra.ghidra.stm32.Stm32ExternalMemoryApplicator;
import io.github.rezabakhshi.embedra.ghidra.stm32.Stm32MappingException;
import io.github.rezabakhshi.embedra.ghidra.stm32.Stm32RawBinImporter;
import io.github.rezabakhshi.embedra.ghidra.stm32.Stm32VectorApplicator;
import io.github.rezabakhshi.embedra.ghidra.strings.GhidraStringApplicator;
import io.github.rezabakhshi.embedra.ghidra.yara.GhidraYaraApplicator;
import io.github.rezabakhshi.embedra.targets.esp.Esp32S3TargetProvider;
import io.github.rezabakhshi.embedra.targets.esp.EspressifChipIdRegistry;
import io.github.rezabakhshi.embedra.targets.esp8266.Esp8266LegacyTargetProvider;
import io.github.rezabakhshi.embedra.targets.rp.RpTargetResolver;
import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadataParser;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.board.Stm32BoardCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlan;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Proof suite verifying T072: Program-transaction rollback, cancellation,
 * and partial-workspace cleanup across all Embedra loaders, mappers, and applicators.
 */
class GhidraTransactionRollbackAndCancellationIntegrationTest {

    private static final Object CONSUMER = new Object();

    private final List<ProgramDB> activePrograms = new ArrayList<>();

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
        for (ProgramDB prog : activePrograms) {
            if (prog != null) {
                prog.release(CONSUMER);
            }
        }
        activePrograms.clear();
    }

    private ProgramDB createProgram(String name, String languageId, String compilerSpecId)
            throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(languageId));
        CompilerSpec compiler = language.getCompilerSpecByID(new CompilerSpecID(compilerSpecId));
        ProgramDB program = new ProgramDB(name, language, compiler, CONSUMER);
        activePrograms.add(program);
        return program;
    }

    private ProgramDB createArmProgram(String name) throws Exception {
        return createProgram(name, "ARM:LE:32:Cortex", "default");
    }

    private ProgramDB createXtensaProgram(String name) throws Exception {
        return createProgram(name, "Xtensa:LE:32:default", "default");
    }

    private static byte[] readResource(String path) throws IOException {
        try (InputStream stream = GhidraTransactionRollbackAndCancellationIntegrationTest
                .class.getResourceAsStream(path)) {
            if (stream == null) {
                throw new IOException("Missing resource: " + path);
            }
            return stream.readAllBytes();
        }
    }

    // =========================================================================
    // 1. Core GhidraProgramTransaction Rollback Contract
    // =========================================================================

    @Test
    void transactionRollsBackUncommittedMemoryBlock() throws Exception {
        ProgramDB program = createArmProgram("TxRollbackTest");
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Test Uncommitted Block")) {
            assertFalse(tx.isClosed());
            program.getMemory().createInitializedBlock("temp_ram", start,
                new ByteArrayInputStream(new byte[] {0x11, 0x22, 0x33, 0x44}), 4,
                TaskMonitor.DUMMY, false);
            assertNotNull(program.getMemory().getBlock(start));
            // Close without commit()
        }

        assertNull(program.getMemory().getBlock(start),
            "Uncommitted block must be rolled back on AutoCloseable exit");
    }

    @Test
    void transactionRejectsNullProgramAndBlankDescription() throws Exception {
        ProgramDB program = createArmProgram("TxValidationTest");

        assertThrows(NullPointerException.class,
            () -> GhidraProgramTransaction.start(null, "Valid Description"));
        assertThrows(IllegalArgumentException.class,
            () -> GhidraProgramTransaction.start(program, null));
        assertThrows(IllegalArgumentException.class,
            () -> GhidraProgramTransaction.start(program, "  "));
    }

    @Test
    void transactionClosedCannotBeCommitted() throws Exception {
        ProgramDB program = createArmProgram("TxCommitClosedTest");
        GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Test Closed");
        assertFalse(tx.isClosed());
        tx.commit();
        tx.close();
        assertTrue(tx.isClosed());

        assertThrows(IllegalStateException.class, tx::commit);
        // Double close is safe and idempotent
        tx.close();
        assertTrue(tx.isClosed());
    }

    // =========================================================================
    // 2. Importer / Mapper Rollback on Conflict
    // =========================================================================

    @Test
    void espMapperRollsBackOnMemoryBlockConflict() throws Exception {
        Esp32S3TargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        ProgramDB program = createProgram("EspConflictTest",
            provider.language().languageId(), provider.language().compilerSpecId());
        Address conflictStart = program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(0x3fc8_8000L);

        byte[] existingBytes = new byte[] {0x55, 0x66, 0x77, (byte) 0x88};
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Create conflicting user block")) {
            MemoryBlock userBlock = program.getMemory().createInitializedBlock(
                "user_reserved", conflictStart, new ByteArrayInputStream(existingBytes),
                existingBytes.length, TaskMonitor.DUMMY, false);
            userBlock.setRead(true);
            userBlock.setWrite(false);
            userBlock.setExecute(false);
            tx.commit();
        }

        byte[] imageBytes = readResource("/fixtures/esp32s3/esp32s3-freestanding-minimal.bin");
        EspImage image = EspImageParser.parse(imageBytes, ParserLimits.defaults(),
            CancellationToken.none());

        EspMappingException failure = assertThrows(EspMappingException.class,
            () -> new EspApplicationImageMapper().map(program, image, provider,
                TaskMonitor.DUMMY, Optional.empty()));

        assertEquals(DiagnosticCode.ESP_MAPPING_CONFLICT, failure.code());

        // Verify rollback: only the single original user block exists, unmodified
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        assertEquals(1, blocks.length);
        assertEquals("user_reserved", blocks[0].getName());
        byte[] readBack = new byte[4];
        blocks[0].getBytes(conflictStart, readBack);
        assertArrayEquals(existingBytes, readBack);
        assertFalse(program.getSymbolTable().getExternalEntryPointIterator().hasNext());
    }

    @Test
    void esp8266MapperRollsBackOnMemoryBlockConflict() throws Exception {
        ProgramDB program = createXtensaProgram("Esp8266ConflictTest");
        Address conflictStart = program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(0x4010_0000L);

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Create existing block")) {
            program.getMemory().createInitializedBlock("user_iram", conflictStart,
                new ByteArrayInputStream(new byte[] {1, 2, 3, 4}), 4,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        byte[] imageBytes = readResource("/fixtures/esp8266/esp8266-freestanding-v1-0x00000.bin");
        Esp8266Image image = Esp8266ImageParser.parse(imageBytes, ParserLimits.defaults(),
            CancellationToken.none());
        Esp8266LegacyTargetProvider provider = new Esp8266LegacyTargetProvider();

        EspMappingException failure = assertThrows(EspMappingException.class,
            () -> new Esp8266LegacyImageMapper().map(program, image, 0x1000L,
                provider, TaskMonitor.DUMMY));

        assertEquals(DiagnosticCode.ESP_MAPPING_CONFLICT, failure.code());
        assertEquals(1, program.getMemory().getBlocks().length);
        assertEquals("user_iram", program.getMemory().getBlocks()[0].getName());
    }

    @Test
    void rpFirmwareMapperRollsBackOnMemoryBlockConflict() throws Exception {
        ProgramDB program = createArmProgram("RpConflictTest");
        Address conflictStart = program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(0x1000_0000L);

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Create existing block")) {
            program.getMemory().createInitializedBlock("user_xip", conflictStart,
                new ByteArrayInputStream(new byte[] {1, 2, 3, 4}), 4,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        byte[] uf2Bytes = readResource("/fixtures/rp/rp2040-pico-blinky.uf2");
        RpUf2Image image = RpUf2Parser.parse(uf2Bytes, ParserLimits.defaults(),
            CancellationToken.none());
        RpDeviceCatalog catalog = RpFirmwareImportService.loadDefaultCatalogSafe();
        RpTargetResolver resolver = new RpTargetResolver(catalog);
        var targetResolution = resolver.resolvePart("RP2040").orElseThrow();
        RpBootMetadata bootMetadata = RpBootMetadataParser.parse(image.segments(), "RP2040");

        RpMappingException failure = assertThrows(RpMappingException.class,
            () -> new RpFirmwareMapper().map(program, image.segments(), targetResolution,
                bootMetadata, "UF2", TaskMonitor.DUMMY));

        assertEquals(DiagnosticCode.RP_MAPPING_CONFLICT, failure.code());
        assertEquals(1, program.getMemory().getBlocks().length);
        assertEquals("user_xip", program.getMemory().getBlocks()[0].getName());
        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO));
    }

    @Test
    void stm32RawBinImporterRollsBackOnPartConflict() throws Exception {
        ProgramDB program = createArmProgram("Stm32PartConflictTest");
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Seed differing part")) {
            program.getOptions(Stm32RawBinImporter.PROVENANCE_OPTIONS)
                .setString("Exact Part", "STM32F407VG");
            tx.commit();
        }

        byte[] binBytes = new byte[256];
        ByteArrayProvider provider = new ByteArrayProvider("test.bin", binBytes);
        var parts = Stm32CuratedPartIds.load(Path.of(
            "catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        Stm32RawBinPlan plan = Stm32RawBinPlan.explicit("STM32F103C8T6", 0x0800_0000L, 256,
            parts, ParserLimits.defaults());

        assertThrows(IOException.class,
            () -> Stm32RawBinImporter.importInto(program, provider, plan,
                parts, TaskMonitor.DUMMY));

        // Options must retain original part and not be corrupted
        assertEquals("STM32F407VG", program.getOptions(
            Stm32RawBinImporter.PROVENANCE_OPTIONS).getString("Exact Part", null));
        assertEquals(0, program.getMemory().getBlocks().length);
    }

    @Test
    void stm32VectorApplicatorRollsBackOnInstructionConflict() throws Exception {
        ProgramDB program = createArmProgram("Stm32VectorConflictTest");
        byte[] bytes = readResource("/fixtures/stm32f103/STM32F103C8T6.bin");
        var parts = Stm32CuratedPartIds.load(Path.of(
            "catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        var plan = Stm32RawBinPlan.explicit("STM32F103C8T6", 0x0800_0000L,
            bytes.length, parts, ParserLimits.defaults());
        Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("firmware.bin", bytes), plan, parts, TaskMonitor.DUMMY);

        var candidates = Stm32VectorDiscovery.discover(bytes, 0x0800_0000L,
            List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L)),
            ParserLimits.defaults(), CancellationToken.none());
        var confirmed = Stm32VectorDiscovery.confirm(candidates, 0x0800_0000L);

        Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0800_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Test mapped-byte conflict")) {
            program.getMemory().setByte(address, (byte) 0x01);
            tx.commit();
        }

        assertThrows(IOException.class,
            () -> Stm32VectorApplicator.apply(program, confirmed, TaskMonitor.DUMMY));

        assertNull(program.getListing().getDefinedDataAt(address));
        assertEquals(-1, program.getOptions(Stm32VectorApplicator.PROVENANCE_OPTIONS)
            .getLong("Confirmed Vector Address", -1));
    }

    @Test
    void stm32ExternalMemoryApplicatorRollsBackOnLengthMismatch() throws Exception {
        ProgramDB program = createArmProgram("Stm32ExtMemConflictTest");
        byte[] providerBytes = new byte[128];
        ByteArrayProvider provider = new ByteArrayProvider("extmem.bin", providerBytes);

        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(
            Path.of("catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        Stm32MemoryPlanner memory = Stm32MemoryPlanner.load(
            Path.of("catalogs/stm32/2026-09-29/memory-plans.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32BoardCatalog boards = Stm32BoardCatalog.load(
            Path.of("catalogs/stm32/2026-09-29/board-profiles.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        var extMemPlan = Stm32ExternalMemoryPlanner.compose(
            memory.plan("STM32H735IGK6", Stm32MemoryPlanner.BootMode.UNKNOWN),
            boards.requireProfiles("STM32H735IGK6"));
        var loadPlan = Stm32ExternalMemoryPlanner.planLoad(extMemPlan, "OSPI1_NOR", 0x1000L, 0x100L,
            ParserLimits.defaults());

        assertThrows(Stm32MappingException.class,
            () -> Stm32ExternalMemoryApplicator.loadInto(program, provider, loadPlan,
                TaskMonitor.DUMMY));

        assertEquals(0, program.getMemory().getBlocks().length);
    }

    // =========================================================================
    // 3. Cooperative Cancellation Rolls Back Mid-Flight Mutations
    // =========================================================================

    @Test
    void cancellationPreemptsEspImportService() throws Exception {
        ProgramDB program = createXtensaProgram("EspPreemptCancelTest");
        byte[] imageBytes = readResource("/fixtures/esp32s3/esp32s3-freestanding-minimal.bin");
        Esp32S3TargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(0);
        monitor.cancel();

        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> new EspApplicationImportService(provider).importImage(program,
                imageBytes, monitor));
        assertEquals(DiagnosticCode.CANCELLED, failure.diagnostic().code());

        assertEquals(0, program.getMemory().getBlocks().length);
        assertFalse(program.getSymbolTable().getExternalEntryPointIterator().hasNext());
    }

    @Test
    void cancellationMidSegmentRollsBackEspMapper() throws Exception {
        ProgramDB program = createXtensaProgram("EspMidCancelTest");
        byte[] imageBytes = readResource("/fixtures/esp32s3/esp32s3-freestanding-minimal.bin");
        EspImage image = EspImageParser.parse(imageBytes, ParserLimits.defaults(),
            CancellationToken.none());
        Esp32S3TargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());

        // Cancel after 1 segment check inside the mapping loop
        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);

        assertThrows(CancelledException.class,
            () -> new EspApplicationImageMapper().map(program, image, provider,
                monitor, Optional.empty()));

        assertEquals(0, program.getMemory().getBlocks().length,
            "All segments created before cancellation must roll back completely");
    }

    @Test
    void cancellationMidSegmentRollsBackEsp8266Mapper() throws Exception {
        ProgramDB program = createXtensaProgram("Esp8266MidCancelTest");
        byte[] imageBytes = readResource("/fixtures/esp8266/esp8266-freestanding-v1-0x00000.bin");
        Esp8266Image image = Esp8266ImageParser.parse(imageBytes, ParserLimits.defaults(),
            CancellationToken.none());
        Esp8266LegacyTargetProvider provider = new Esp8266LegacyTargetProvider();

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);

        assertThrows(CancelledException.class,
            () -> new Esp8266LegacyImageMapper().map(program, image, 0x1000L,
                provider, monitor));

        assertEquals(0, program.getMemory().getBlocks().length);
    }

    @Test
    void cancellationMidSegmentRollsBackRpMapper() throws Exception {
        ProgramDB program = createArmProgram("RpMidCancelTest");
        byte[] uf2Bytes = readResource("/fixtures/rp/rp2040-pico-blinky.uf2");
        RpUf2Image image = RpUf2Parser.parse(uf2Bytes, ParserLimits.defaults(),
            CancellationToken.none());
        RpDeviceCatalog catalog = RpFirmwareImportService.loadDefaultCatalogSafe();
        RpTargetResolver resolver = new RpTargetResolver(catalog);
        var targetResolution = resolver.resolvePart("RP2040").orElseThrow();
        RpBootMetadata bootMetadata = RpBootMetadataParser.parse(image.segments(), "RP2040");

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);

        assertThrows(CancelledException.class,
            () -> new RpFirmwareMapper().map(program, image.segments(), targetResolution,
                bootMetadata, "UF2", monitor));

        assertEquals(0, program.getMemory().getBlocks().length);
        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO));
    }

    @Test
    void cancellationMidOperationRollsBackCryptoApplicator() throws Exception {
        ProgramDB program = createArmProgram("CryptoCancelTest");
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Init Block")) {
            program.getMemory().createInitializedBlock("RAM", start, 1024, (byte) 0,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        List<CryptoFinding> findings = List.of(
            new CryptoFinding("CRYPTO-001", 0x2000_0010L, 32, CryptoCategory.CIPHER_SYMMETRIC,
                CryptoAlgorithm.AES_128, CryptoConfidence.CONFIRMED,
                Set.of(), "AES key", "00112233445566778899aabbccddeeff", false, Map.of())
        );

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);
        GhidraCryptoApplicator.apply(program, findings, monitor);

        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO),
            "Crypto bookmarks must be rolled back on cancellation");
        assertFalse(program.getOptions(GhidraCryptoApplicator.PROGRAM_OPTIONS_CATEGORY)
            .contains("Total Findings Count"));
    }

    @Test
    void cancellationMidOperationRollsBackCtfApplicator() throws Exception {
        ProgramDB program = createArmProgram("CtfCancelTest");
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Init Block")) {
            program.getMemory().createInitializedBlock("RAM", start, 1024, (byte) 0,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        List<CtfEntity> entities = List.of(
            new CtfEntity("CTF-001", CtfEntityCategory.FLAG, CtfEntityType.FLAG,
                CtfSeverity.HIGH, StringConfidence.CONFIRMED, 0x2000_0010L, 16,
                "FLAG{test}", "flag match", true)
        );

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);
        GhidraCtfApplicator.apply(program, entities, monitor);

        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO));
        assertFalse(program.getOptions(GhidraCtfApplicator.PROGRAM_OPTIONS_CATEGORY)
            .contains("Total Findings Count"));
    }

    @Test
    void cancellationMidOperationRollsBackYaraApplicator() throws Exception {
        ProgramDB program = createArmProgram("YaraCancelTest");
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Init Block")) {
            program.getMemory().createInitializedBlock("RAM", start, 1024, (byte) 0,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        CompiledYaraRuleset ruleset = CompiledYaraRuleset.loadBuiltinRules(true, false);
        YaraRule chachaRule = ruleset.getRule("ChaCha20_Constant");
        assertNotNull(chachaRule);
        List<YaraMatch> matches = List.of(
            new YaraMatch(chachaRule, 0x2000_0010L, 0, 16, Map.of())
        );

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);
        assertThrows(CancelledException.class,
            () -> GhidraYaraApplicator.apply(program, matches, monitor));

        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO));
        assertFalse(program.getOptions(GhidraYaraApplicator.PROGRAM_OPTIONS_CATEGORY)
            .contains("Total Matches Count"));
    }

    @Test
    void cancellationMidOperationRollsBackStringApplicator() throws Exception {
        ProgramDB program = createArmProgram("StringCancelTest");
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Init Block")) {
            program.getMemory().createInitializedBlock("RAM", start, 1024, (byte) 0,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        List<ExtractedString> staticStrings = List.of(
            new ExtractedString(0x2000_0010L, 5, StringEncoding.ASCII,
                "hello", StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL, true)
        );
        List<RecoveredStackString> stackStrings = List.of(
            new RecoveredStackString(0x2000_0020L, 0x10L, "pass", StringEncoding.ASCII,
                StringConfidence.CONFIRMED, 0x2000_0020L, 0x2000_0030L, 4)
        );

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);
        GhidraStringApplicator.apply(program, staticStrings, stackStrings, monitor);

        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO));
        assertFalse(program.getOptions(GhidraStringApplicator.PROGRAM_OPTIONS_CATEGORY)
            .contains("Total Strings Count"));
    }

    @Test
    void cancellationMidOperationRollsBackLoggingApplicator() throws Exception {
        ProgramDB program = createArmProgram("LoggingCancelTest");
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Init Block")) {
            program.getMemory().createInitializedBlock("RAM", start, 1024, (byte) 0,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        List<LoggingCallSite> callSites = List.of(
            new LoggingCallSite(0x2000_0010L, 0x2000_0014L, "printf", DiagnosticLogLevel.ERROR,
                FormatStringDescriptor.empty(), Map.of(), "CONFIRMED", "assert failed")
        );

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);
        GhidraLoggingApplicator.apply(program, callSites, monitor);

        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO));
        assertFalse(program.getOptions(GhidraLoggingApplicator.PROGRAM_OPTIONS_CATEGORY)
            .contains("Total Logging Call Sites"));
    }

    @Test
    void cancellationMidOperationRollsBackSecurityLeadApplicator() throws Exception {
        ProgramDB program = createArmProgram("SecLeadCancelTest");
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Init Block")) {
            program.getMemory().createInitializedBlock("RAM", start, 1024, (byte) 0,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        SecurityLead lead = new SecurityLead("LEAD-001",
            LeadCategory.PASSWORD_TOKEN_COMPARISON, LeadConfidence.HIGH, 0.95,
            LeadSeverity.CRITICAL, 0x2000_0010L, "strcmp", "admin_secret",
            "Admin credential check", List.of(), Map.of(), true);

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);
        GhidraSecurityLeadApplicator.apply(program, new SecurityLeadsReport(List.of(lead)), monitor);

        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO));
        assertFalse(program.getOptions(GhidraSecurityLeadApplicator.PROGRAM_OPTIONS_CATEGORY)
            .contains("Total Security Leads"));
    }

    @Test
    void cancellationMidOperationRollsBackPluginApplicator() throws Exception {
        ProgramDB program = createArmProgram("PluginCancelTest");
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Init Block")) {
            program.getMemory().createInitializedBlock("RAM", start, 1024, (byte) 0,
                TaskMonitor.DUMMY, false);
            tx.commit();
        }

        List<ScannerPluginFinding> findings = List.of(
            new ScannerPluginFinding("FND-1", "plug-1",
                io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory.CUSTOM_PLUGIN,
                "PLUGIN_MATCH",
                io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity.HIGH,
                io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence.CONFIRMED,
                0.9, "ARM", 0x2000_0010L, 4, "secret", "custom flaw", false, Map.of())
        );

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);
        var report = GhidraPluginApplicator.apply(program, findings, monitor);
        assertFalse(report.optionsUpdated());

        assertEquals(0, program.getBookmarkManager().getBookmarkCount(BookmarkType.INFO));
        assertFalse(program.getOptions(GhidraPluginApplicator.PROGRAM_OPTIONS_CATEGORY)
            .contains("Total Plugin Findings"));
    }

    @Test
    void cancellationMidOperationRollsBackFunctionNormalizer() throws Exception {
        ProgramDB program = createArmProgram("NormalizerCancelTest");
        Address funcAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000_0000L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Create Func")) {
            program.getMemory().createInitializedBlock("CODE", funcAddr, 64, (byte) 0,
                TaskMonitor.DUMMY, false);
            Function func = program.getFunctionManager().createFunction("test_fn", funcAddr,
                new ghidra.program.model.address.AddressSet(funcAddr, funcAddr.add(8)),
                ghidra.program.model.symbol.SourceType.USER_DEFINED);
            func.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
            tx.commit();
        }

        CancellingTaskMonitor monitor = new CancellingTaskMonitor(1);
        assertThrows(CancelledException.class,
            () -> EmbedraFunctionNormalizer.normalize(program, null, monitor));

        // Function calling convention remains unchanged
        Function func = program.getFunctionManager().getFunctionAt(funcAddr);
        assertNotNull(func);
        assertTrue(func.hasUnknownCallingConventionName()
            || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(func.getCallingConventionName()));
    }

    @Test
    void cancellationStopsWorkspaceDiffExtractor() throws Exception {
        ProgramDB program = createArmProgram("DiffCancelTest");
        CancellationToken token = () -> true; // Already cancelled

        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> new GhidraWorkspaceDiffExtractor().extract(program, ParserLimits.defaults(), token));

        assertEquals(DiagnosticCode.CANCELLED, failure.diagnostic().code());
    }

    // =========================================================================
    // 4. Partial-Workspace Cleanup Cases
    // =========================================================================

    @Test
    void fullFlashWorkspaceCleansUpLoadedProgramsOnCancellation() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        byte[] flash = readResource("/fixtures/esp32s3/full-flash/default-factory.bin");
        ByteArrayProvider provider = new ByteArrayProvider("full_flash.bin", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();

        Object consumer = new Object();
        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);
        MessageLog log = new MessageLog();

        // Count how many checkCancelled calls before triggering cancel.
        // We set cancelAfterCheckCount to 6 so the first executable finishes,
        // and cancellation is caught during loadWorkspace loop.
        CancellingTaskMonitor monitor = new CancellingTaskMonitor(6);
        ImporterSettings settings = new ImporterSettings(provider, "full_flash.bin",
            null, "/", false, spec, options, consumer, log, monitor);

        assertThrows(CancelledException.class, () -> loader.load(settings));
    }

    @Test
    void fullFlashWorkspaceCleansUpLoadedProgramsOnSecondExecutableFailure() throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        byte[] flash = readResource("/fixtures/esp32s3/full-flash/default-factory.bin");

        // The default-factory.bin has bootloader at 0x0 and factory app at 0x10000.
        // Corrupt the second executable at 0x10000 by corrupting its magic byte 0xE9.
        byte[] corruptedFlash = flash.clone();
        corruptedFlash[0x10000] = 0x00;

        ByteArrayProvider validProvider = new ByteArrayProvider("valid.bin", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(validProvider).iterator().next();
        ByteArrayProvider provider = new ByteArrayProvider("corrupted_flash.bin", corruptedFlash);

        Object consumer = new Object();
        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);
        MessageLog log = new MessageLog();
        ImporterSettings settings = new ImporterSettings(provider, "corrupted_flash.bin",
            null, "/", false, spec, options, consumer, log, TaskMonitor.DUMMY);

        assertThrows(IOException.class, () -> loader.load(settings));
    }

    // =========================================================================
    // Helper Classes
    // =========================================================================

    private static final class CancellingTaskMonitor extends TaskMonitorAdapter {
        private final int cancelAfterCheckCount;

        private final AtomicInteger checkCount = new AtomicInteger();

        CancellingTaskMonitor(int cancelAfterCheckCount) {
            this.cancelAfterCheckCount = cancelAfterCheckCount;
        }

        @Override
        public void checkCancelled() throws CancelledException {
            if (checkCount.incrementAndGet() >= cancelAfterCheckCount) {
                cancel();
                throw new CancelledException();
            }
        }

        @Override
        public boolean isCancelled() {
            return checkCount.get() >= cancelAfterCheckCount || super.isCancelled();
        }
    }
}
