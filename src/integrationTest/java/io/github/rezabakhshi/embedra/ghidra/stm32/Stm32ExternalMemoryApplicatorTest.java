package io.github.rezabakhshi.embedra.ghidra.stm32;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32RawBinPlan;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.stm32.board.Stm32BoardCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlan;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlanner
    .Stm32ExternalMemoryLoadPlan;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Real-Ghidra transaction, idempotence, preservation, and binding tests for T047. */
class Stm32ExternalMemoryApplicatorTest {
    private static final Object CONSUMER = new Object();

    private static final String PART = "STM32H735IGK6";

    private static final long OSPI1_NOR = 0x90000000L;

    private static final long OSPI2_RAM = 0x70000000L;

    private ProgramDB program;

    private Stm32ExternalMemoryPlan plan;

    private Stm32ExternalMemoryLoadPlan loadPlan;

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
        program = new ProgramDB("STM32 external memory test", language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(
            Path.of("catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        Stm32MemoryPlanner memory = Stm32MemoryPlanner.load(
            Path.of("catalogs/stm32/2026-09-29/memory-plans.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32BoardCatalog boards = Stm32BoardCatalog.load(
            Path.of("catalogs/stm32/2026-09-29/board-profiles.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        plan = Stm32ExternalMemoryPlanner.compose(
            memory.plan(PART, Stm32MemoryPlanner.BootMode.UNKNOWN), boards.requireProfiles(PART));
        loadPlan = Stm32ExternalMemoryPlanner.planLoad(plan, "OSPI1_NOR", 0x1000L, 0x100L,
            ParserLimits.defaults());
        byte[] bytes = fixture();
        Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("neutral.bin", bytes),
            Stm32RawBinPlan.explicit(PART, 0x08000000L, bytes.length, selection,
                ParserLimits.defaults()), selection, TaskMonitor.DUMMY);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void mapsPinnedAperturesAsUninitializedBlocksWithPinnedPermissions() throws Exception {
        Stm32ExternalMemoryReport report = Stm32ExternalMemoryApplicator.mapWindows(program,
            plan, TaskMonitor.DUMMY);

        assertTrue(report.committed());
        assertEquals(Stm32ExternalMemoryApplicator.OPERATION_MAP_WINDOWS, report.operation());
        assertEquals(PART, report.exactPart());
        assertEquals(2, report.createdBlocks().size());
        MemoryBlock nor = program.getMemory().getBlock(address(OSPI1_NOR));
        assertNotNull(nor);
        assertEquals(0x4000000L, nor.getSize());
        assertFalse(nor.isInitialized());
        assertTrue(nor.isRead());
        assertTrue(nor.isWrite());
        assertFalse(nor.isExecute());
        assertEquals("embedra_extmem_ospi1_nor", nor.getName());
        MemoryBlock ram = program.getMemory().getBlock(address(OSPI2_RAM));
        assertNotNull(ram);
        assertEquals(0x1000000L, ram.getSize());
        assertTrue(ram.isWrite());
        assertNotNull(program.getSymbolTable().getPrimarySymbol(address(OSPI1_NOR)));
        var options = program.getOptions(Stm32ExternalMemoryApplicator.EXTERNAL_MEMORY_OPTIONS);
        assertEquals(PART, options.getString("Exact Part", ""));
        assertEquals("PINNED_T042_BOARD_PROFILE", options.getString("Source", ""));
        assertEquals("STM32H735G-DK", options.getString("Board", ""));
        assertTrue(options.getString("Created Blocks", "").contains("embedra_extmem_ospi1_nor"));
    }

    @Test
    void windowMappingIsIdempotentAndPreservesUserBlocks() throws Exception {
        Stm32ExternalMemoryApplicator.mapWindows(program, plan, TaskMonitor.DUMMY);
        Stm32ExternalMemoryReport second = Stm32ExternalMemoryApplicator.mapWindows(program,
            plan, TaskMonitor.DUMMY);
        assertEquals(0, second.createdBlocks().size());
        assertEquals(0, second.createdSymbols().size());

        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Add user block")) {
            MemoryBlock user = program.getMemory().createUninitializedBlock("user_window",
                address(0x80000000L), 0x1000L, false);
            user.setRead(true);
            transaction.commit();
        }
        Stm32ExternalMemoryApplicator.mapWindows(program, plan, TaskMonitor.DUMMY);
        assertNotNull(program.getMemory().getBlock("user_window"));
    }

    @Test
    void mappingPreservesAnOverlappingUserBlockWithoutCreation() throws Exception {
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Reserve the NOR aperture")) {
            MemoryBlock user = program.getMemory().createUninitializedBlock("user_window",
                address(OSPI1_NOR), 0x1000L, false);
            user.setRead(true);
            transaction.commit();
        }

        Stm32ExternalMemoryReport report = Stm32ExternalMemoryApplicator.mapWindows(program,
            plan, TaskMonitor.DUMMY);

        assertNull(program.getMemory().getBlock("embedra_extmem_ospi1_nor"));
        assertNotNull(program.getMemory().getBlock("user_window"));
        assertTrue(report.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("MEMORY_PRESERVED") && conflict.address() == OSPI1_NOR
                && conflict.detail().contains("user_window")));
        // The untouched window is still mapped.
        assertNotNull(program.getMemory().getBlock(address(OSPI2_RAM)));
    }

    @Test
    void deletedWindowBlocksAreNeverResurrected() throws Exception {
        Stm32ExternalMemoryApplicator.mapWindows(program, plan, TaskMonitor.DUMMY);
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Delete the NOR aperture block")) {
            program.getMemory().removeBlock(program.getMemory()
                .getBlock(address(OSPI1_NOR)), TaskMonitor.DUMMY);
            transaction.commit();
        }

        Stm32ExternalMemoryReport second = Stm32ExternalMemoryApplicator.mapWindows(program,
            plan, TaskMonitor.DUMMY);

        assertNull(program.getMemory().getBlock(address(OSPI1_NOR)));
        assertTrue(second.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("PRESERVED_ABSENT") && conflict.address() == OSPI1_NOR));
        assertEquals(0, second.createdBlocks().size());
    }

    @Test
    void loadsBytesAtThePlannedApertureAddress() throws Exception {
        byte[] payload = new byte[0x100];
        for (int index = 0; index < payload.length; index++) {
            payload[index] = (byte) index;
        }

        Stm32ExternalMemoryReport report = Stm32ExternalMemoryApplicator.loadInto(program,
            new ByteArrayProvider("payload.bin", payload), loadPlan, TaskMonitor.DUMMY);

        assertTrue(report.committed());
        assertEquals(Stm32ExternalMemoryApplicator.OPERATION_LOAD_BYTES, report.operation());
        assertEquals(0x100L, report.loadedByteCount());
        Address target = address(loadPlan.cpuAddress());
        assertEquals(0x90001000L, target.getOffset());
        MemoryBlock block = program.getMemory().getBlock(target);
        assertNotNull(block);
        assertEquals(0x100L, block.getSize());
        assertTrue(block.isInitialized());
        assertTrue(block.isWrite());
        assertFalse(block.isExecute());
        byte[] mapped = new byte[payload.length];
        assertEquals(payload.length, program.getMemory().getBytes(target, mapped));
        assertArrayEquals(payload, mapped);
        assertNotNull(program.getSymbolTable().getPrimarySymbol(target));
        assertEquals("OSPI1_NOR", program.getOptions(
            Stm32ExternalMemoryApplicator.EXTERNAL_MEMORY_OPTIONS).getString("Device", ""));
    }

    @Test
    void byteLoadsAreIdempotentNeverResurrectAndPreserveContent() throws Exception {
        byte[] payload = new byte[0x100];
        payload[0] = 0x42;
        Stm32ExternalMemoryApplicator.loadInto(program,
            new ByteArrayProvider("payload.bin", payload), loadPlan, TaskMonitor.DUMMY);

        Stm32ExternalMemoryReport second = Stm32ExternalMemoryApplicator.loadInto(program,
            new ByteArrayProvider("payload.bin", payload), loadPlan, TaskMonitor.DUMMY);
        assertEquals(0, second.createdBlocks().size());
        assertEquals(0, second.createdSymbols().size());

        byte[] different = new byte[0x100];
        different[0] = 0x24;
        Stm32ExternalMemoryReport third = Stm32ExternalMemoryApplicator.loadInto(program,
            new ByteArrayProvider("other.bin", different), loadPlan, TaskMonitor.DUMMY);
        assertTrue(third.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("CONTENT_DIFFERS")));
        byte[] mapped = new byte[payload.length];
        program.getMemory().getBytes(address(loadPlan.cpuAddress()), mapped);
        assertArrayEquals(payload, mapped);

        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Delete the load block")) {
            program.getMemory().removeBlock(program.getMemory()
                .getBlock(address(loadPlan.cpuAddress())), TaskMonitor.DUMMY);
            transaction.commit();
        }
        Stm32ExternalMemoryReport fourth = Stm32ExternalMemoryApplicator.loadInto(program,
            new ByteArrayProvider("payload.bin", payload), loadPlan, TaskMonitor.DUMMY);
        assertNull(program.getMemory().getBlock(address(loadPlan.cpuAddress())));
        assertTrue(fourth.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("PRESERVED_ABSENT")));
    }

    @Test
    void truncatedAndOversizedInputsFailClosedWithoutMutation() throws Exception {
        byte[] payload = new byte[0x100];

        assertThrows(Stm32MappingException.class,
            () -> Stm32ExternalMemoryApplicator.loadInto(program,
                new ByteArrayProvider("short.bin", new byte[0x80]), loadPlan,
                TaskMonitor.DUMMY));
        assertThrows(Stm32MappingException.class,
            () -> Stm32ExternalMemoryApplicator.loadInto(program,
                new ByteArrayProvider("long.bin", new byte[0x180]), loadPlan,
                TaskMonitor.DUMMY));

        assertNull(program.getMemory().getBlock(address(loadPlan.cpuAddress())));
        assertNull(program.getOptions(Stm32ExternalMemoryApplicator.EXTERNAL_MEMORY_OPTIONS)
            .getString("Exact Part", null));
    }

    @Test
    void applicationIsBoundToTheRecordedExactPart() throws Exception {
        byte[] payload = new byte[0x100];
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Record a different part")) {
            program.getOptions(Stm32RawBinImporter.PROVENANCE_OPTIONS)
                .setString("Exact Part", "STM32F103C8T6");
            transaction.commit();
        }
        assertThrows(Stm32MappingException.class,
            () -> Stm32ExternalMemoryApplicator.loadInto(program,
                new ByteArrayProvider("payload.bin", payload), loadPlan, TaskMonitor.DUMMY));
        assertNull(program.getMemory().getBlock(address(loadPlan.cpuAddress())));

        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(
            Path.of("catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        Stm32MemoryPlanner memory = Stm32MemoryPlanner.load(
            Path.of("catalogs/stm32/2026-09-29/memory-plans.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32BoardCatalog boards = Stm32BoardCatalog.load(
            Path.of("catalogs/stm32/2026-09-29/board-profiles.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32ExternalMemoryPlan f103Plan = Stm32ExternalMemoryPlanner.compose(
            memory.plan("STM32F103C8T6", Stm32MemoryPlanner.BootMode.UNKNOWN),
            boards);
        assertFalse(f103Plan.mapped());
        assertThrows(Stm32MappingException.class,
            () -> Stm32ExternalMemoryApplicator.mapWindows(program, f103Plan,
                TaskMonitor.DUMMY));
        assertNull(program.getMemory().getBlock(address(OSPI1_NOR)));
    }

    @Test
    void aProgramWithoutRecordedProvenanceIsRejected() throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("ARM:LE:32:Cortex"));
        ProgramDB fresh = new ProgramDB("unbound external memory test", language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
        try {
            byte[] payload = new byte[0x100];
            assertThrows(Stm32MappingException.class,
                () -> Stm32ExternalMemoryApplicator.loadInto(fresh,
                    new ByteArrayProvider("payload.bin", payload), loadPlan,
                    TaskMonitor.DUMMY));
            assertNull(fresh.getMemory().getBlock(fresh.getAddressFactory()
                .getDefaultAddressSpace().getAddress(loadPlan.cpuAddress())));
            assertThrows(Stm32MappingException.class,
                () -> Stm32ExternalMemoryApplicator.mapWindows(fresh, plan,
                    TaskMonitor.DUMMY));
            assertNull(fresh.getMemory().getBlock(fresh.getAddressFactory()
                .getDefaultAddressSpace().getAddress(OSPI1_NOR)));
        }
        finally {
            fresh.release(CONSUMER);
        }
    }

    @Test
    void loadingIntoAMappedAperturePreservesTheWindow() throws Exception {
        Stm32ExternalMemoryApplicator.mapWindows(program, plan, TaskMonitor.DUMMY);
        byte[] payload = new byte[0x100];

        Stm32ExternalMemoryReport report = Stm32ExternalMemoryApplicator.loadInto(program,
            new ByteArrayProvider("payload.bin", payload), loadPlan, TaskMonitor.DUMMY);

        assertNull(program.getMemory()
            .getBlock("embedra_extmem_ospi1_nor_load_1000"));
        assertTrue(report.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("MEMORY_PRESERVED")));
        assertNotNull(program.getMemory().getBlock(address(OSPI1_NOR)));
    }

    @Test
    void cancellationMidApplicationRollsTheTransactionBack() throws Exception {
        RecordingMonitor monitor = new RecordingMonitor(3);
        assertThrows(CancelledException.class, () -> Stm32ExternalMemoryApplicator.mapWindows(
            program, plan, monitor));
        assertNull(program.getMemory().getBlock(address(OSPI1_NOR)));
        assertNull(program.getMemory().getBlock(address(OSPI2_RAM)));
        assertNull(program.getOptions(Stm32ExternalMemoryApplicator.EXTERNAL_MEMORY_OPTIONS)
            .getString("Exact Part", null));
        assertTrue(monitor.cancelled);
    }

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static byte[] fixture() throws IOException {
        try (InputStream input = Stm32ExternalMemoryApplicatorTest.class
                .getResourceAsStream("/fixtures/stm32-core-samples/" + PART + ".bin")) {
            return java.util.Objects.requireNonNull(input).readAllBytes();
        }
    }

    /** A monitor that cancels after N observed cancellation checks. */
    @SuppressWarnings("deprecation")
    private static final class RecordingMonitor implements TaskMonitor {
        private final int cancelAfter;

        private int checks;

        private boolean cancelled;

        private RecordingMonitor(int cancelAfter) {
            this.cancelAfter = cancelAfter;
        }

        @Override
        public void checkCanceled() throws CancelledException {
            checks++;
            if (checks >= cancelAfter) {
                cancelled = true;
                throw new CancelledException();
            }
        }

        @Override
        public boolean isCancelled() {
            return cancelled;
        }

        @Override
        public void setMessage(String message) {
        }

        @Override
        public String getMessage() {
            return "";
        }

        @Override
        public void setProgress(long value) {
        }

        @Override
        public long getProgress() {
            return 0;
        }

        @Override
        public void initialize(long total) {
        }

        @Override
        public void setMaximum(long max) {
        }

        @Override
        public long getMaximum() {
            return 0;
        }

        @Override
        public void setIndeterminate(boolean indeterminate) {
        }

        @Override
        public boolean isIndeterminate() {
            return true;
        }

        @Override
        public void incrementProgress(long incrementAmount) {
        }

        @Override
        public void cancel() {
        }

        @Override
        public void addCancelledListener(CancelledListener listener) {
        }

        @Override
        public void removeCancelledListener(CancelledListener listener) {
        }

        @Override
        public void setCancelEnabled(boolean enable) {
        }

        @Override
        public boolean isCancelEnabled() {
            return true;
        }

        @Override
        public void clearCanceled() {
        }

        @Override
        public void setShowProgressValue(boolean showProgressValue) {
        }
    }
}
