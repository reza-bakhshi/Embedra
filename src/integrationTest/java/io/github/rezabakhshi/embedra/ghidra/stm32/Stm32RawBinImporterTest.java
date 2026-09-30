package io.github.rezabakhshi.embedra.ghidra.stm32;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32RawBinPlan;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Stm32RawBinImporterTest {
    private static final Object CONSUMER = new Object();

    private ProgramDB program;

    private Stm32CuratedPartIds parts;

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getenv("GHIDRA_INSTALL_DIR"))), configuration);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("ARM:LE:32:Cortex"));
        program = new ProgramDB("STM32 raw BIN test", language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
        parts = Stm32CuratedPartIds.load(Path.of(
            "catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void importsF103GoldenAtExplicitBaseAndRecordsSelection() throws Exception {
        byte[] bytes = fixture("stm32f103", "STM32F103C8T6.bin");
        Stm32RawBinPlan plan = Stm32RawBinPlan.explicit(
            "STM32F103C8T6", 0x08000000L, bytes.length, parts, ParserLimits.defaults());

        Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("neutral.dat", bytes), plan, parts, TaskMonitor.DUMMY);

        Address base = address(0x08000000L);
        MemoryBlock block = program.getMemory().getBlock(base);
        assertNotNull(block);
        assertEquals(bytes.length, block.getSize());
        byte[] mapped = new byte[bytes.length];
        assertEquals(bytes.length, program.getMemory().getBytes(base, mapped));
        assertArrayEquals(bytes, mapped);
        var evidence = program.getOptions(Stm32RawBinImporter.PROVENANCE_OPTIONS);
        assertEquals("STM32F103C8T6", evidence.getString("Exact Part", ""));
        assertEquals(0x08000000L, evidence.getLong("Explicit Base", -1));
        assertEquals(bytes.length, evidence.getLong("Input Length", -1));
        assertEquals("EXPLICIT", evidence.getString("Base Selection", ""));
        assertNull(program.getMemory().getBlock(address(0)));
    }

    @Test
    void importsRamResidentN6GoldenWithoutAssumingInternalFlash() throws Exception {
        byte[] bytes = fixture("stm32-core-samples", "STM32N657X0H3Q.bin");
        Stm32RawBinPlan plan = Stm32RawBinPlan.explicit(
            "STM32N657X0H3Q", 0x34000000L, bytes.length, parts, ParserLimits.defaults());

        Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("ram.bin", bytes), plan, parts, TaskMonitor.DUMMY);

        assertNotNull(program.getMemory().getBlock(address(0x34000000L)));
        assertNull(program.getMemory().getBlock(address(0x08000000L)));
    }

    @Test
    void mismatchedBytesAndConflictingMappingsLeaveProgramUnchanged() throws Exception {
        byte[] bytes = fixture("stm32f103", "STM32F103C8T6.bin");
        Stm32RawBinPlan plan = Stm32RawBinPlan.explicit(
            "STM32F103C8T6", 0x08000000L, bytes.length, parts, ParserLimits.defaults());
        assertThrows(IOException.class, () -> Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("short.bin", new byte[8]), plan, parts, TaskMonitor.DUMMY));
        assertNull(program.getMemory().getBlock(address(0x08000000L)));

        ByteArrayProvider provider = new ByteArrayProvider("valid.bin", bytes);
        Stm32RawBinImporter.importInto(program, provider, plan, parts, TaskMonitor.DUMMY);
        assertThrows(IOException.class, () -> Stm32RawBinImporter.importInto(program,
            provider, plan, parts, TaskMonitor.DUMMY));
        byte[] mapped = new byte[bytes.length];
        assertEquals(bytes.length,
            program.getMemory().getBytes(address(0x08000000L), mapped));
        assertArrayEquals(bytes, mapped);
    }

    @Test
    void importerRejectsAPlanWithoutPinnedPartMembership() throws Exception {
        byte[] bytes = fixture("stm32f103", "STM32F103C8T6.bin");
        Stm32RawBinPlan unverified = Stm32RawBinPlan.explicit(
            "STM32UNKNOWN", 0x08000000L, bytes.length, part -> true,
            ParserLimits.defaults());

        assertThrows(IOException.class, () -> Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("unknown.bin", bytes), unverified, parts,
            TaskMonitor.DUMMY));
        assertNull(program.getMemory().getBlock(address(0x08000000L)));
    }

    @Test
    void importerDoesNotMixExactPartsInOneProgram() throws Exception {
        byte[] bytes = fixture("stm32f103", "STM32F103C8T6.bin");
        Stm32RawBinPlan first = Stm32RawBinPlan.explicit(
            "STM32F103C8T6", 0x08000000L, bytes.length, parts, ParserLimits.defaults());
        Stm32RawBinImporter.importInto(program, new ByteArrayProvider("first.bin", bytes),
            first, parts, TaskMonitor.DUMMY);
        Stm32RawBinPlan other = Stm32RawBinPlan.explicit(
            "STM32C051C8T6", 0x08001000L, bytes.length, parts, ParserLimits.defaults());

        assertThrows(IOException.class, () -> Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("other.bin", bytes), other, parts, TaskMonitor.DUMMY));

        assertNull(program.getMemory().getBlock(address(0x08001000L)));
        assertEquals("STM32F103C8T6", program.getOptions(
            Stm32RawBinImporter.PROVENANCE_OPTIONS).getString("Exact Part", ""));
    }

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static byte[] fixture(String folder, String filename) throws IOException {
        try (InputStream input = Stm32RawBinImporterTest.class.getResourceAsStream(
                "/fixtures/" + folder + "/" + filename)) {
            return java.util.Objects.requireNonNull(input).readAllBytes();
        }
    }
}
