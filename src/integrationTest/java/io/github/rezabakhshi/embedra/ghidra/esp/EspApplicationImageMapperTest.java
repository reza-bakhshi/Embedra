package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.esp.Esp32S3TargetProvider;
import io.github.rezabakhshi.embedra.targets.esp.EspressifChipIdRegistry;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EspApplicationImageMapperTest {
    private static final Object CONSUMER = new Object();

    private ProgramDB program;

    private EspImage image;

    private Esp32S3TargetProvider provider;

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

    @BeforeEach
    void setUp() throws Exception {
        provider = new Esp32S3TargetProvider(EspressifChipIdRegistry.loadBundled());
        image = EspImageParser.parseForChip(fixture(), 9, ParserLimits.defaults(),
            CancellationToken.none());
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(provider.language().languageId()));
        CompilerSpec compiler = language.getCompilerSpecByID(
            new CompilerSpecID(provider.language().compilerSpecId()));
        program = new ProgramDB("Embedra ESP32-S3 mapping test", language, compiler, CONSUMER);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void mapsExactSegmentBytesAddressesPermissionsAndEntry() throws Exception {
        EspImportReport report = new EspApplicationImageMapper().map(
            program, image, provider, TaskMonitor.DUMMY);

        assertBlock("esp_segment_0_drom", 0x3c01_0020L, 296,
            true, false, false, image.segments().get(0).data());
        assertBlock("esp_segment_1_dram", 0x3fc8_8000L, 4,
            true, true, false, image.segments().get(1).data());
        assertBlock("esp_segment_2_iram", 0x4037_8000L, 36,
            true, false, true, image.segments().get(2).data());

        Address entry = address(image.header().entryPoint());
        assertTrue(program.getSymbolTable().isExternalEntryPoint(entry));
        Symbol entrySymbol = program.getSymbolTable().getPrimarySymbol(entry);
        assertNotNull(entrySymbol);
        assertEquals("entry", entrySymbol.getName());

        assertTrue(report.committed());
        assertEquals("esp32s3", report.deviceId());
        assertEquals(provider.language().languageId(), report.languageId());
        assertEquals(provider.language().compilerSpecId(), report.compilerSpecId());
        assertEquals(3, report.segments().size());
        assertEquals(image.header().entryPoint(), report.entryPoint().orElseThrow());
    }

    @Test
    void mappingConflictPreservesExistingBlockAndLeavesNoPartialImport() throws Exception {
        byte[] existingBytes = new byte[] {0x11, 0x22, 0x33, 0x44};
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Create user block")) {
            MemoryBlock existing = program.getMemory().createInitializedBlock("user_dram",
                address(0x3fc8_8000L), new ByteArrayInputStream(existingBytes),
                existingBytes.length, TaskMonitor.DUMMY, false);
            existing.setRead(true);
            existing.setWrite(false);
            existing.setExecute(false);
            transaction.commit();
        }

        EspMappingException failure = assertThrows(EspMappingException.class,
            () -> new EspApplicationImageMapper().map(
                program, image, provider, TaskMonitor.DUMMY));

        assertEquals(DiagnosticCode.ESP_MAPPING_CONFLICT, failure.code());
        assertTrue(failure.getMessage().contains("0x3fc88000"));
        assertNull(program.getMemory().getBlock(address(0x3c01_0020L)));
        assertNull(program.getMemory().getBlock(address(0x4037_8000L)));
        MemoryBlock preserved = program.getMemory().getBlock(address(0x3fc8_8000L));
        assertNotNull(preserved);
        assertEquals("user_dram", preserved.getName());
        assertTrue(preserved.isRead());
        assertFalse(preserved.isWrite());
        assertFalse(preserved.isExecute());
        assertBytes(preserved.getStart(), existingBytes);
        assertFalse(program.getSymbolTable().isExternalEntryPoint(
            address(image.header().entryPoint())));
    }

    @Test
    void realProgramTransactionRollsBackUncommittedMemoryMutation() throws Exception {
        Address start = address(0x4037_0000L);
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Rollback test block")) {
            assertFalse(transaction.isClosed());
            program.getMemory().createInitializedBlock("must_rollback", start,
                new ByteArrayInputStream(new byte[] {1, 2, 3, 4}), 4,
                TaskMonitor.DUMMY, false);
            assertNotNull(program.getMemory().getBlock(start));
        }

        assertNull(program.getMemory().getBlock(start));
    }

    private void assertBlock(String name, long start, int size, boolean readable,
            boolean writable, boolean executable, byte[] expectedBytes) throws Exception {
        MemoryBlock block = program.getMemory().getBlock(address(start));
        assertNotNull(block);
        assertEquals(name, block.getName());
        assertEquals(start, block.getStart().getOffset());
        assertEquals(start + size - 1L, block.getEnd().getOffset());
        assertEquals(size, block.getSize());
        assertEquals(readable, block.isRead());
        assertEquals(writable, block.isWrite());
        assertEquals(executable, block.isExecute());
        assertBytes(block.getStart(), expectedBytes);
    }

    private void assertBytes(Address start, byte[] expectedBytes) throws Exception {
        byte[] actual = new byte[expectedBytes.length];
        assertEquals(expectedBytes.length, program.getMemory().getBytes(start, actual));
        assertArrayEquals(expectedBytes, actual);
    }

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static byte[] fixture() throws IOException {
        try (InputStream input = EspApplicationImageMapperTest.class.getResourceAsStream(
                "/fixtures/esp32s3/esp32s3-freestanding-minimal.bin")) {
            assertNotNull(input, "missing T008 fixture");
            return input.readAllBytes();
        }
    }
}
