package io.github.rezabakhshi.embedra.ghidra.stm32;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.io.ByteArrayInputStream;
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
    void f103PlanKeepsUnknownBytesUninitializedAndBoundsTheRealFixture() throws Exception {
        var planner = Stm32MemoryPlanner.load(Path.of("catalogs/stm32/2026-09-29/memory-plans.json"),
            parts, ParserLimits.defaults(), CancellationToken.none());
        var memoryPlan = planner.plan("STM32F103C8T6", Stm32MemoryPlanner.BootMode.UNKNOWN);
        byte[] bytes = fixture("stm32f103", "STM32F103C8T6.bin");
        var imagePlan = Stm32RawBinPlan.explicit("STM32F103C8T6", 0x08000000L,
            bytes.length, parts, ParserLimits.defaults());
        assertTrue(bytes.length < memoryPlan.regions().getFirst().range().length());
        Stm32RawBinImporter.importInto(program, new ByteArrayProvider("neutral.dat", bytes),
            imagePlan, parts, TaskMonitor.DUMMY);
        int transaction = program.startTransaction("Materialize representative pure plan");
        try {
            for (var region : memoryPlan.regions()) {
                long offset = region.kind().equals("FLASH") ? bytes.length : 0;
                MemoryBlock block = program.getMemory().createUninitializedBlock(region.id() + "_unknown",
                    address(region.range().start() + offset), region.range().length() - offset, false);
                block.setRead(true);
                block.setWrite(region.access().contains("w"));
                block.setExecute(region.access().contains("x"));
                assertFalse(block.isInitialized());
            }
            program.endTransaction(transaction, true);
        }
        catch (Exception exception) {
            program.endTransaction(transaction, false);
            throw exception;
        }
        assertEquals(0x0800ffffL, program.getMemory().getBlock(address(0x0800ffffL)).getEnd().getOffset());
        assertNull(program.getMemory().getBlock(address(0x08010000L)));
        assertNull(program.getMemory().getBlock(address(0)));
        assertNull(program.getMemory().getBlock(address(0x22000000L)));
        assertFalse(program.getMemory().getBlock(address(0x1ffff000L)).isInitialized());
        assertThrows(ghidra.program.model.mem.MemoryAccessException.class,
            () -> program.getMemory().getByte(address(0x1ffff000L)));
        byte[] mapped = new byte[bytes.length];
        program.getMemory().getBytes(address(0x08000000L), mapped);
        assertArrayEquals(bytes, mapped);
    }

    @Test
    void g491CcmAliasSharesBackingBytesAndDoesNotCreatePhysicalCapacity() throws Exception {
        var planner = Stm32MemoryPlanner.load(Path.of("catalogs/stm32/2026-09-29/memory-plans.json"),
            parts, ParserLimits.defaults(), CancellationToken.none());
        var plan = planner.plan("STM32G491RET6", Stm32MemoryPlanner.BootMode.UNKNOWN);
        byte[] sample = {0x12, 0x34, 0x56, 0x78};
        int transaction = program.startTransaction("Representative G491 alias");
        try {
            for (var region : plan.regions()) {
                if (!region.kind().equals("RAM")) {
                    continue;
                }
                long prefix = region.id().equals("CCM") ? sample.length : 0;
                if (prefix != 0) {
                    program.getMemory().createInitializedBlock("CCM_sample", address(region.range().start()),
                        new ByteArrayInputStream(sample), sample.length, TaskMonitor.DUMMY, false);
                }
                program.getMemory().createUninitializedBlock(region.id(), address(region.range().start() + prefix),
                    region.range().length() - prefix, false);
            }
            var alias = plan.aliases().getFirst();
            var target = plan.regions().stream().filter(r -> r.id().equals(alias.target())).findFirst().orElseThrow();
            program.getMemory().createByteMappedBlock(alias.id(), address(alias.range().start()),
                address(target.range().start()), alias.range().length(), false);
            byte[] mapped = new byte[sample.length];
            program.getMemory().getBytes(address(alias.range().start()), mapped);
            assertArrayEquals(sample, mapped);
            program.getMemory().setByte(address(alias.range().start() + 1), (byte) 0x6a);
            assertEquals((byte) 0x6a, program.getMemory().getByte(address(target.range().start() + 1)));
            assertThrows(ghidra.program.model.mem.MemoryAccessException.class,
                () -> program.getMemory().getByte(address(alias.range().endExclusive() - 1)));
            program.endTransaction(transaction, true);
        }
        catch (Exception exception) {
            program.endTransaction(transaction, false);
            throw exception;
        }
        assertEquals(112 * 1024, plan.regions().stream().filter(r -> r.kind().equals("RAM"))
            .mapToLong(r -> r.range().length()).sum());
        assertNull(program.getMemory().getBlock(address(0x2001c000L)));
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
