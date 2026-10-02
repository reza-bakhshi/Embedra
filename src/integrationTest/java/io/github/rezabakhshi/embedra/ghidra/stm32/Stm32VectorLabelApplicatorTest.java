package io.github.rezabakhshi.embedra.ghidra.stm32;

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
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32RawBinPlan;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32VectorDiscovery;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32InterruptPlan;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Stm32VectorLabelApplicatorTest {
    private static final Object CONSUMER = new Object();

    private static final long BASE = 0x08000000L;

    private ProgramDB program;

    private Stm32CuratedPartIds selection;

    private Stm32InterruptPlan.Entry entry;

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
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("ARM:LE:32:Cortex"));
        program = new ProgramDB("STM32 vector label test", language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
        selection = Stm32CuratedPartIds.load(Path.of(
            "catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        entry = Stm32InterruptPlan.load(Path.of(
            "catalogs/stm32/2026-09-29/curated-catalog.json"), selection,
            ParserLimits.defaults(), CancellationToken.none()).requireEntry("STM32F103C8T6");
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void createsResetCoreAndDeviceLabelsAndFunctions() throws Exception {
        byte[] bytes = importFixture();
        setVector(16, (BASE + 0x110L) | 1L);

        Stm32VectorApplicationReport report = apply(confirmed(bytes));

        assertTrue(report.committed());
        assertEquals("STM32F103C8T6", report.exactPart());
        assertEquals(entry.interrupts().size() > 0, report.namedSlotCount() > 0);
        assertTrue(report.createdFunctionCount() > 0);
        assertNotNull(functionName(BASE + 0x100L));
        assertEquals("STM32F103C8T6_Reset", functionName(BASE + 0x100L));
        assertEquals("STM32F103C8T6_NonMaskableInt", functionName(BASE + 0x104L));
        assertEquals("STM32F103C8T6_WWDG_IRQn", functionName(BASE + 0x110L));
        assertTrue(hasSymbol(BASE + 0x110L, "STM32F103C8T6_WWDG_IRQn"));
        assertEquals("USER_CONFIRMED", report.confirmationMethod());
        assertEquals(BASE, program.getOptions(Stm32VectorLabelApplicator.LABEL_OPTIONS)
            .getLong("Vector Table Address", -1));
        assertEquals("STM32F103C8T6", program.getOptions(
            Stm32VectorLabelApplicator.LABEL_OPTIONS).getString("Exact Part", ""));
        assertFalse(program.getOptions(Stm32VectorLabelApplicator.LABEL_OPTIONS)
            .getString("Source SHA-256", "").isBlank());
    }

    @Test
    void appliesFromT039MemoryPlanWithoutHardCodedRange() throws Exception {
        byte[] bytes = importFixture();
        Stm32MemoryPlanner planner = Stm32MemoryPlanner.load(Path.of(
            "catalogs/stm32/2026-09-29/memory-plans.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32VectorApplicationReport report = Stm32VectorLabelApplicator.apply(program,
            confirmed(bytes), entry, planner.plan("STM32F103C8T6",
                Stm32MemoryPlanner.BootMode.UNKNOWN), TaskMonitor.DUMMY);
        assertTrue(report.committed());
        assertEquals("STM32F103C8T6_Reset", functionName(BASE + 0x100L));
    }

    @Test
    void rejectsInterruptListForAnotherExactPartWithoutMutation() throws Exception {
        byte[] bytes = importFixture();
        Stm32InterruptPlan full = Stm32InterruptPlan.load(Path.of(
            "catalogs/stm32/2026-09-29/curated-catalog.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32InterruptPlan.Entry other = full.requireEntry("STM32F401RET6");

        assertThrows(Stm32MappingException.class,
            () -> Stm32VectorLabelApplicator.apply(program, confirmed(bytes), other,
                BASE, 0x1000L, TaskMonitor.DUMMY));

        assertNull(functionName(BASE + 0x100L));
        assertNull(program.getListing().getDefinedDataAt(address(BASE)));
        assertNull(program.getOptions(Stm32VectorLabelApplicator.LABEL_OPTIONS)
            .getString("Exact Part", null));
    }

    @Test
    void repeatedApplicationCreatesNothingNew() throws Exception {
        byte[] bytes = importFixture();
        apply(confirmed(bytes));
        Stm32VectorApplicationReport second = apply(confirmed(bytes));
        assertEquals(0, second.createdFunctionCount());
        assertEquals(0, second.createdLabelCount());
        assertTrue(second.createdFunctionAddresses().isEmpty());
        assertTrue(second.createdSymbols().isEmpty());
    }

    @Test
    void preservesUserFunctionsSymbolsAndData() throws Exception {
        byte[] bytes = importFixture();
        setVector(16, (BASE + 0x110L) | 1L);
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Add user artifacts")) {
            program.getFunctionManager().createFunction("user_core_handler",
                address(BASE + 0x104L), new ghidra.program.model.address.AddressSet(
                    address(BASE + 0x104L)), SourceType.USER_DEFINED);
            program.getListing().createData(address(BASE + 0x110L),
                ghidra.program.model.data.ByteDataType.dataType);
            program.getSymbolTable().createLabel(address(BASE + 0x108L),
                "STM32F103C8T6_WWDG_IRQn", SourceType.USER_DEFINED);
            transaction.commit();
        }

        Stm32VectorApplicationReport report = apply(confirmed(bytes));

        assertEquals("user_core_handler", functionName(BASE + 0x104L));
        assertNotNull(program.getListing().getDefinedDataAt(address(BASE + 0x110L)));
        assertTrue(report.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("FUNCTION_PRESERVED")
                && conflict.address() == BASE + 0x104L));
        assertTrue(report.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("DATA_PRESERVED")
                && conflict.address() == BASE + 0x110L));
        assertTrue(report.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("NAME_CONFLICT")
                && conflict.address() == BASE + 0x110L));
        assertFalse(report.createdFunctionAddresses().contains(BASE + 0x104L));
        assertEquals("STM32F103C8T6_Reset", functionName(BASE + 0x100L));
    }

    @Test
    void doesNotResurrectDeletedArtifacts() throws Exception {
        byte[] bytes = importFixture();
        apply(confirmed(bytes));
        assertNotNull(functionName(BASE + 0x100L));
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Delete reset handler")) {
            program.getFunctionManager().removeFunction(address(BASE + 0x100L));
            transaction.commit();
        }
        assertNull(functionName(BASE + 0x100L));

        Stm32VectorApplicationReport second = apply(confirmed(bytes));

        assertNull(functionName(BASE + 0x100L));
        assertEquals(0, second.createdFunctionCount());
        assertTrue(second.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("PRESERVED_ABSENT")
                && conflict.address() == BASE + 0x100L));
    }

    @Test
    void ambiguousInterruptListAppliesNothing() throws Exception {
        byte[] bytes = importFixture();
        Stm32InterruptPlan.Entry ambiguous = new Stm32InterruptPlan.Entry(
            "STM32N657X0H3Q", "CONDITIONAL_REVIEW", "stm32n657xx.h", List.of());

        assertThrows(Stm32MappingException.class,
            () -> Stm32VectorLabelApplicator.apply(program, confirmed(bytes), ambiguous,
                BASE, bytes.length, TaskMonitor.DUMMY));

        assertNull(functionName(BASE + 0x100L));
        assertNull(program.getListing().getDefinedDataAt(address(BASE)));
        assertNull(program.getOptions(Stm32VectorLabelApplicator.LABEL_OPTIONS)
            .getString("Exact Part", null));
    }

    @Test
    void truncatedTableFailsClosedWithoutMutation() throws Exception {
        List<Long> words = new ArrayList<>(Collections.nCopies(16, 0L));
        words.set(0, 0x20005000L);
        words.set(1, BASE + 0x100L | 1L);
        var candidate = new Stm32VectorDiscovery.Candidate(0, BASE, 0x20005000L,
            BASE + 0x100L | 1L, words, 100, "digest");
        var confirmed = Stm32VectorDiscovery.confirm(List.of(candidate), BASE);
        byte[] shortBlock = new byte[8];
        writeLittleEndian(shortBlock, 0, 0x20005000L);
        writeLittleEndian(shortBlock, 4, BASE + 0x100L | 1L);
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Create short vector block")) {
            program.getMemory().createInitializedBlock("vectors", address(BASE),
                new java.io.ByteArrayInputStream(shortBlock), shortBlock.length,
                TaskMonitor.DUMMY, false);
            transaction.commit();
        }

        assertThrows(Stm32MappingException.class,
            () -> Stm32VectorLabelApplicator.apply(program, confirmed, entry, BASE,
                BASE + 0x1000L, TaskMonitor.DUMMY));
        assertNull(program.getFunctionManager().getFunctionAt(address(BASE + 0x100L)));
    }

    private byte[] importFixture() throws Exception {
        byte[] bytes = fixture();
        var plan = Stm32RawBinPlan.explicit("STM32F103C8T6", BASE, bytes.length, selection,
            ParserLimits.defaults());
        Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("firmware.bin", bytes), plan, selection, TaskMonitor.DUMMY);
        return bytes;
    }

    private Stm32VectorDiscovery.Confirmed confirmed(byte[] bytes) throws Exception {
        var candidates = Stm32VectorDiscovery.discover(bytes, BASE,
            List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L)),
            ParserLimits.defaults(), CancellationToken.none());
        return Stm32VectorDiscovery.confirm(candidates, BASE);
    }

    private Stm32VectorApplicationReport apply(Stm32VectorDiscovery.Confirmed confirmed)
            throws Exception {
        return Stm32VectorLabelApplicator.apply(program, confirmed, entry, BASE, 0x1000L,
            TaskMonitor.DUMMY);
    }

    private void setVector(int slot, long value) throws Exception {
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Set device vector")) {
            program.getMemory().setInt(address(BASE + slot * 4L), (int) value);
            transaction.commit();
        }
    }

    private String functionName(long offset) {
        var function = program.getFunctionManager().getFunctionAt(address(offset));
        return function == null ? null : function.getName();
    }

    private boolean hasSymbol(long offset, String name) {
        return java.util.Arrays.stream(program.getSymbolTable().getSymbols(address(offset)))
            .anyMatch(symbol -> symbol.getName().equals(name));
    }

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static void writeLittleEndian(byte[] target, int offset, long value) {
        for (int index = 0; index < 4; index++) {
            target[offset + index] = (byte) (value >>> (index * 8));
        }
    }

    private byte[] fixture() throws IOException {
        try (InputStream input = Objects.requireNonNull(getClass().getResourceAsStream(
                "/fixtures/stm32f103/STM32F103C8T6.bin"))) {
            return input.readAllBytes();
        }
    }
}
