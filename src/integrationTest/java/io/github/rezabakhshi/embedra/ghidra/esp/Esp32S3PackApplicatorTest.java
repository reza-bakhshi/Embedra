package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.pack.Esp32S3PackLoader;
import io.github.rezabakhshi.embedra.pack.EspPeripheralPack;
import io.github.rezabakhshi.embedra.pack.EspRomSymbolPack;
import io.github.rezabakhshi.embedra.pack.EspSvdPack;
import io.github.rezabakhshi.embedra.pack.EspSvdPackLoader;
import io.github.rezabakhshi.embedra.svd.EspSvdAccess;
import io.github.rezabakhshi.embedra.svd.EspSvdDevice;
import io.github.rezabakhshi.embedra.svd.EspSvdEnumeratedValue;
import io.github.rezabakhshi.embedra.svd.EspSvdField;
import io.github.rezabakhshi.embedra.svd.EspSvdPeripheral;
import io.github.rezabakhshi.embedra.svd.EspSvdRegister;
import io.github.rezabakhshi.embedra.targets.esp.Esp32S3TargetProvider;
import io.github.rezabakhshi.embedra.targets.esp.EspressifChipIdRegistry;
import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.OptionalLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Esp32S3PackApplicatorTest {
    private static final Object CONSUMER = new Object();

    private ProgramDB program;

    private EspRomSymbolPack rom;

    private EspPeripheralPack peripherals;

    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getenv("GHIDRA_INSTALL_DIR"))), configuration);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        Esp32S3TargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        Language language = DefaultLanguageServiceHolder.language(
            provider.language().languageId());
        CompilerSpec compiler = language.getCompilerSpecByID(
            new CompilerSpecID(provider.language().compilerSpecId()));
        program = new ProgramDB("ESP32-S3 pack test", language, compiler, CONSUMER);
        rom = Esp32S3PackLoader.loadRom(
            pack("espressif.esp32s3.rom"), ParserLimits.defaults(),
            CancellationToken.none());
        peripherals = Esp32S3PackLoader.loadPeripherals(
            pack("espressif.esp32s3.peripherals"), ParserLimits.defaults(),
            CancellationToken.none());
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void appliesSymbolsRegistersAliasesAndTypesWithoutOverwritingUserNames()
            throws Exception {
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Create user ROM evidence")) {
            MemoryBlock block = program.getMemory().createUninitializedBlock("user_rom",
                address(0x4000_0000L), 0x60000, false);
            block.setRead(true);
            block.setExecute(true);
            program.getSymbolTable().createLabel(address(0x4000_05d0L),
                "my_printf", SourceType.USER_DEFINED);
            transaction.commit();
        }

        EspPackApplicationReport first = new Esp32S3PackApplicator().apply(
            program, rom, peripherals, TaskMonitor.DUMMY);

        assertTrue(first.committed());
        assertTrue(first.createdSymbols().size() > 3000);
        assertTrue(first.createdDataAddresses().size() > 1000,
            "created data: " + first.createdDataAddresses().size()
                + ", conflicts: " + first.conflicts().size());
        assertTrue(first.conflicts().stream().anyMatch(
            conflict -> conflict.address() == 0x4000_0000L));
        assertEquals("my_printf", program.getSymbolTable()
            .getPrimarySymbol(address(0x4000_05d0L)).getName());
        assertTrue(Arrays.stream(program.getSymbolTable().getSymbols(
            address(0x4000_05d0L))).anyMatch(symbol -> symbol.getName().equals("ets_printf")));

        MemoryBlock gpio = program.getMemory().getBlock(address(0x6000_4004L));
        assertNotNull(gpio);
        assertTrue(gpio.isRead());
        assertTrue(gpio.isWrite());
        assertFalse(gpio.isExecute());
        assertNotNull(program.getListing().getDefinedDataAt(address(0x6000_4004L)));
        assertTrue(Arrays.stream(program.getSymbolTable().getSymbols(
            address(0x6000_4004L))).anyMatch(
                symbol -> symbol.getName().equals("GPIO_OUT_REG")));
        assertTrue(Arrays.stream(program.getSymbolTable().getSymbols(
            address(0x6002_6000L))).anyMatch(symbol -> symbol.getName().equals("SYSCON")));
        assertTrue(Arrays.stream(program.getSymbolTable().getSymbols(
            address(0x6002_6000L))).anyMatch(symbol -> symbol.getName().equals("APB_CTRL")));

        EspPackApplicationReport second = new Esp32S3PackApplicator().apply(
            program, rom, peripherals, TaskMonitor.DUMMY);
        assertTrue(second.committed());
        assertEquals(0, second.createdSymbols().size());
        assertEquals(0, second.createdBlocks().size());
        assertEquals(0, second.createdDataAddresses().size());
    }

    @Test
    void removesOnlyArtifactsNamedByTheApplicationReceipt() throws Exception {
        Esp32S3PackApplicator applicator = new Esp32S3PackApplicator();
        EspPackApplicationReport application = applicator.apply(
            program, rom, peripherals, TaskMonitor.DUMMY);

        EspPackRemovalReport removal = applicator.remove(
            program, application, TaskMonitor.DUMMY);

        assertTrue(removal.committed());
        assertTrue(removal.conflicts().isEmpty(), removal.conflicts().toString());
        assertNull(program.getMemory().getBlock(address(0x4000_05d0L)));
        assertNull(program.getMemory().getBlock(address(0x6000_4004L)));
        assertEquals(0, program.getSymbolTable().getSymbols(address(0x4000_05d0L)).length);
    }

    @Test
    void cancellationBeforeApplicationLeavesProgramUnchanged() {
        TaskMonitor monitor = new TaskMonitorAdapter();
        monitor.setCancelEnabled(true);
        monitor.cancel();

        assertThrows(ghidra.util.exception.CancelledException.class,
            () -> new Esp32S3PackApplicator().apply(program, rom, peripherals, monitor));
        assertNull(program.getMemory().getBlock(address(0x4000_05d0L)));
        assertNull(program.getMemory().getBlock(address(0x6000_4004L)));
    }

    @Test
    void appliesSvdRegisterTypesFieldsDescriptionsAndCryptoNamesIdempotently()
            throws Exception {
        EspSvdPack svd = EspSvdPackLoader.load(pack("espressif.esp32s3.svd"),
            ParserLimits.defaults(), CancellationToken.none());
        Esp32S3SvdApplicator applicator = new Esp32S3SvdApplicator();

        EspSvdApplicationReport first = applicator.apply(program, svd,
            TaskMonitor.DUMMY);

        assertTrue(first.committed());
        assertTrue(first.createdBlocks().size() > 40);
        assertTrue(first.createdDataAddresses().size() > 4000);
        assertTrue(first.createdComments() > 4000);
        Address mode = address(0x6003_a040L);
        assertNotNull(program.getListing().getDefinedDataAt(mode));
        assertTrue(program.getListing().getDefinedDataAt(mode).getDataType()
            .getName().contains("AES_MODE"));
        assertTrue(Arrays.stream(program.getSymbolTable().getSymbols(mode))
            .anyMatch(symbol -> symbol.getName().equals("AES_MODE_REG")));
        assertTrue(program.getListing().getComment(
            ghidra.program.model.listing.CommentType.EOL, mode).contains("AES Mode"));

        EspSvdApplicationReport second = applicator.apply(program, svd,
            TaskMonitor.DUMMY);
        assertEquals(0, second.createdBlocks().size());
        assertEquals(0, second.createdSymbols().size());
        assertEquals(0, second.createdDataAddresses().size());
        assertEquals(0, second.createdComments());
    }

    @Test
    void annotatesResolvedRomCryptoCallAndRecordsDetectorCoverage() throws Exception {
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Create crypto evidence")) {
            MemoryBlock code = program.getMemory().createUninitializedBlock("code",
                address(0x4200_0000L), 0x100, false);
            code.setRead(true);
            code.setExecute(true);
            MemoryBlock romBlock = program.getMemory().createUninitializedBlock("rom",
                address(0x4000_0000L), 0x20000, false);
            romBlock.setRead(true);
            romBlock.setExecute(true);
            program.getFunctionManager().createFunction("esp_sha256_start",
                address(0x4000_1234L), new AddressSet(address(0x4000_1234L)),
                SourceType.IMPORTED);
            program.getReferenceManager().addMemoryReference(address(0x4200_0010L),
                address(0x4000_1234L), RefType.UNCONDITIONAL_CALL,
                SourceType.ANALYSIS, 0);
            program.getOptions("Embedra ESP32-S3 SVD").setString("Pack ID",
                "espressif.esp32s3.svd");
            transaction.commit();
        }

        EmbedraEsp32S3CryptoAnalyzer analyzer = new EmbedraEsp32S3CryptoAnalyzer();
        assertTrue(analyzer.canAnalyze(program));
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Run crypto analyzer")) {
            assertTrue(analyzer.added(program,
                new AddressSet(address(0x4200_0000L), address(0x4200_00ffL)),
                TaskMonitor.DUMMY, new MessageLog()));
            transaction.commit();
        }

        assertNotNull(program.getBookmarkManager().getBookmark(address(0x4200_0010L),
            "Analysis", "Embedra Crypto"));
        assertEquals(1, program.getOptions("Embedra ESP32-S3 Crypto Analysis")
            .getInt("Finding Count", -1));
        assertTrue(program.getOptions("Embedra ESP32-S3 Crypto Analysis")
            .getString("Unsupported Algorithms", "").contains("software-crypto"));
    }

    @Test
    void appliesAuthoritativeSvdEnumeratedValuesWithoutInferringMissingEnums()
            throws Exception {
        EspSvdPack source = EspSvdPackLoader.load(pack("espressif.esp32s3.svd"),
            ParserLimits.defaults(), CancellationToken.none());
        EspSvdField field = new EspSvdField("MODE", "Key mode", 0, 3,
            EspSvdAccess.READ_WRITE, List.of(new EspSvdEnumeratedValue(
                "AES_256_ENCRYPT", 2, "256-bit encryption")));
        EspSvdRegister register = new EspSvdRegister("MODE", "AES Mode register",
            0x6003_a040L, 32, EspSvdAccess.READ_WRITE, OptionalLong.of(0),
            List.of(field));
        EspSvdPeripheral peripheral = new EspSvdPeripheral("AES",
            "AES accelerator", 0x6003_a000L, 0x6003_a0b8L, List.of(register));
        EspSvdPack fixture = new EspSvdPack(source.manifest(), new EspSvdDevice(
            "ESP32-S3", source.device().sourceRevision(), List.of(peripheral)),
            source.reconciliation());

        new Esp32S3SvdApplicator().apply(program, fixture, TaskMonitor.DUMMY);

        Structure structure = (Structure) program.getListing().getDefinedDataAt(
            address(0x6003_a040L)).getDataType();
        BitFieldDataType bitField = (BitFieldDataType) structure
            .getDefinedComponents()[0].getDataType();
        assertTrue(bitField.getBaseDataType() instanceof Enum);
        assertEquals(2, ((Enum) bitField.getBaseDataType())
            .getValue("AES_256_ENCRYPT"));
    }

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static Path pack(String id) {
        return Path.of("packs", id, "1.0.0");
    }

    private static final class DefaultLanguageServiceHolder {
        private DefaultLanguageServiceHolder() {
        }

        private static Language language(String id) throws Exception {
            return ghidra.program.util.DefaultLanguageService.getLanguageService()
                .getLanguage(new LanguageID(id));
        }
    }
}
