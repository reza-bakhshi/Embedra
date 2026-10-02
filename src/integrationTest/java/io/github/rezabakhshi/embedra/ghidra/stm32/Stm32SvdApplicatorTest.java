package io.github.rezabakhshi.embedra.ghidra.stm32;

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
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.pack.Stm32SvdPack;
import io.github.rezabakhshi.embedra.pack.Stm32SvdPackLoader;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32InterruptPlan;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32SvdApplicability;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Stm32SvdApplicatorTest {
    private static final Object CONSUMER = new Object();

    private static final Path SELECTION = Path.of(
        "catalogs/stm32/2026-09-29/selection.json");

    private static final Path CATALOG = Path.of(
        "catalogs/stm32/2026-09-29/curated-catalog.json");

    private static final Path APPLICABILITY = Path.of(
        "catalogs/stm32/2026-09-29/svd-applicability.json");

    private ProgramDB program;

    private Stm32CuratedPartIds selection;

    private Stm32SvdPack f103;

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
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("ARM:LE:32:Cortex"));
        program = new ProgramDB("STM32 SVD application test", language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
        selection = Stm32CuratedPartIds.load(SELECTION, ParserLimits.defaults(),
            CancellationToken.none());
        f103 = Stm32SvdPackLoader.load(Path.of("packs/stm32.stm32f103.svd/1.0.0"),
            ParserLimits.defaults(), CancellationToken.none());
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void appliesRegisterBlocksTypesEnumsAndProvenance() throws Exception {
        Stm32DeviceDataReport report = Stm32SvdApplicator.applyRegisters(program, f103,
            "STM32F103C8T6", selection, TaskMonitor.DUMMY);

        assertTrue(report.committed());
        assertTrue(report.createdBlocks().size() > 50);
        assertTrue(report.createdSymbols().size() > 500);
        assertEquals(f103.registerCount(), report.registerCount());
        MemoryBlock gpio = program.getMemory().getBlock(address(0x40010800L));
        assertNotNull(gpio);
        assertTrue(gpio.isVolatile());
        assertTrue(gpio.isWrite());
        assertFalse(gpio.isExecute());
        assertTrue(Arrays.stream(program.getSymbolTable().getSymbols(
            address(0x40010800L)))
            .anyMatch(symbol -> symbol.getName().equals("GPIOA_CRL_REG")));
        Structure structure = (Structure) program.getListing()
            .getDefinedDataAt(address(0x40010800L)).getDataType();
        BitFieldDataType bitField = (BitFieldDataType) structure
            .getDefinedComponents()[0].getDataType();
        assertFalse(bitField.getBaseDataType() instanceof Enum);
        assertTrue(program.getListing().getComment(CommentType.EOL,
            address(0x40010804L)).contains("Port configuration register"));
        var options = program.getOptions("Embedra STM32 SVD");
        assertEquals("stm32.stm32f103.svd", options.getString("Pack ID", ""));
        assertEquals("STM32F103C8T6", options.getString("Exact Part", ""));
        assertEquals("CM3", options.getString("Core", ""));
        assertEquals("stm32f1/STM32F103.svd", options.getString("Source File", ""));
    }

    @Test
    void appliesEnumeratedValuesAsGhidraEnums() throws Exception {
        Stm32SvdPack c0 = Stm32SvdPackLoader.load(
            Path.of("packs/stm32.stm32c031.svd/1.0.0"), ParserLimits.defaults(),
            CancellationToken.none());
        Stm32SvdApplicator.applyRegisters(program, c0, "STM32C031C6T3", selection,
            TaskMonitor.DUMMY);
        DataType type = program.getDataTypeManager().getDataType(
            new CategoryPath("/Embedra/STM32C031C6T3/SVD"), "TIM3_CR1_REG_t");
        assertNotNull(type);
        Structure structure = (Structure) type;
        boolean hasEnum = Arrays.stream(structure.getDefinedComponents())
            .anyMatch(component -> component.getDataType() instanceof BitFieldDataType bit
                && bit.getBaseDataType() instanceof Enum);
        assertTrue(hasEnum);
    }

    @Test
    void reapplicationIsIdempotentAndPreservesUserChanges() throws Exception {
        Stm32SvdApplicator.applyRegisters(program, f103, "STM32F103C8T6", selection,
            TaskMonitor.DUMMY);
        Stm32DeviceDataReport second = Stm32SvdApplicator.applyRegisters(program, f103,
            "STM32F103C8T6", selection, TaskMonitor.DUMMY);
        assertEquals(0, second.createdBlocks().size());
        assertEquals(0, second.createdSymbols().size());
        assertEquals(0, second.createdDataAddresses().size());
        assertEquals(0, second.createdComments());

        try (var transaction = io.github.rezabakhshi.embedra.ghidra.transaction
                .GhidraProgramTransaction.start(program, "Add user label")) {
            program.getSymbolTable().createLabel(address(0x40010800L), "user_gpio",
                SourceType.USER_DEFINED);
            transaction.commit();
        }
        Stm32DeviceDataReport third = Stm32SvdApplicator.applyRegisters(program, f103,
            "STM32F103C8T6", selection, TaskMonitor.DUMMY);
        assertTrue(Arrays.stream(program.getSymbolTable().getSymbols(
            address(0x40010800L))).anyMatch(symbol -> symbol.getName().equals("user_gpio")));
        assertEquals(0, third.createdBlocks().size());
    }

    @Test
    void preservesExistingMemoryAndRecordsConflicts() throws Exception {
        try (var transaction = io.github.rezabakhshi.embedra.ghidra.transaction
                .GhidraProgramTransaction.start(program, "Reserve GPIOA")) {
            MemoryBlock reserved = program.getMemory().createUninitializedBlock(
                "user_peripheral", address(0x40010800L), 0x400, false);
            reserved.setRead(true);
            program.getListing().createData(address(0x40010800L),
                ghidra.program.model.data.ByteDataType.dataType);
            transaction.commit();
        }
        Stm32DeviceDataReport report = Stm32SvdApplicator.applyRegisters(program, f103,
            "STM32F103C8T6", selection, TaskMonitor.DUMMY);
        assertNull(program.getMemory().getBlock("embedra_svd_gpioa"));
        assertNotNull(program.getMemory().getBlock("user_peripheral"));
        assertTrue(report.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("MEMORY_PRESERVED")
                && conflict.detail().contains("user_peripheral")));
        assertTrue(report.conflicts().stream().anyMatch(conflict ->
            conflict.kind().equals("TYPE_PRESERVED")
                && conflict.address() == 0x40010800L));
    }

    @Test
    void appliesInterruptsAsAnEnumWithoutVectorLabels() throws Exception {
        Stm32InterruptPlan plan = Stm32InterruptPlan.load(CATALOG, selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32InterruptPlan.Entry entry = plan.requireEntry("STM32F103C8T6");

        Stm32DeviceDataReport report = Stm32SvdApplicator.applyInterrupts(program, entry,
            TaskMonitor.DUMMY);

        assertTrue(report.committed());
        assertEquals(entry.interrupts().size(), report.interruptCount());
        assertEquals(0, report.createdDataAddresses().size());
        Enum irq = (Enum) program.getDataTypeManager().getDataType(
            new CategoryPath("/Embedra/STM32F103C8T6/Interrupts"),
            "STM32F103C8T6_IRQn");
        assertNotNull(irq);
        assertEquals(0, irq.getValue("WWDG_IRQn"));
        assertEquals(entry.interrupts().size(), program.getOptions(
            "Embedra STM32 Interrupts").getInt("Interrupt Count", -1));
        assertEquals(entry.header(), program.getOptions("Embedra STM32 Interrupts")
            .getString("Interrupt Header", ""));
        Stm32DeviceDataReport second = Stm32SvdApplicator.applyInterrupts(program, entry,
            TaskMonitor.DUMMY);
        assertEquals(entry.interrupts().size(), second.interruptCount());
    }

    @Test
    void appliesRegistersAndInterruptsTogetherInOneTransaction() throws Exception {
        Stm32InterruptPlan plan = Stm32InterruptPlan.load(CATALOG, selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32DeviceDataReport report = Stm32SvdApplicator.applyAll(program, f103,
            "STM32F103C8T6", plan.requireEntry("STM32F103C8T6"), selection,
            TaskMonitor.DUMMY);
        assertTrue(report.committed());
        assertTrue(report.createdBlocks().size() > 50);
        assertEquals(plan.requireEntry("STM32F103C8T6").interrupts().size(),
            report.interruptCount());
    }

    @Test
    void rejectsInterruptDefinitionsForAnotherExactPartBeforeApplyingAnything() throws Exception {
        Stm32InterruptPlan plan = Stm32InterruptPlan.load(CATALOG, selection,
            ParserLimits.defaults(), CancellationToken.none());
        assertThrows(Stm32MappingException.class, () -> Stm32SvdApplicator.applyAll(program,
            f103, "STM32F103C8T6", plan.requireEntry("STM32F401RET6"), selection,
            TaskMonitor.DUMMY));
        assertNull(program.getMemory().getBlock(address(0x40010800L)));
        assertNull(program.getDataTypeManager().getDataType(
            new CategoryPath("/Embedra/STM32F103C8T6/Interrupts"),
            "STM32F103C8T6_IRQn"));
    }

    @Test
    void rejectsInterruptEntryForAProgramRecordingAnotherExactPart() throws Exception {
        try (var transaction = io.github.rezabakhshi.embedra.ghidra.transaction
                .GhidraProgramTransaction.start(program, "Record raw part")) {
            program.getOptions(Stm32RawBinImporter.PROVENANCE_OPTIONS)
                .setString("Exact Part", "STM32F103C8T6");
            transaction.commit();
        }
        Stm32InterruptPlan plan = Stm32InterruptPlan.load(CATALOG, selection,
            ParserLimits.defaults(), CancellationToken.none());

        assertThrows(Stm32MappingException.class, () -> Stm32SvdApplicator.applyInterrupts(
            program, plan.requireEntry("STM32F401RET6"), TaskMonitor.DUMMY));

        assertNull(program.getDataTypeManager().getDataType(
            new CategoryPath("/Embedra/STM32F401RET6/Interrupts"), "STM32F401RET6_IRQn"));
    }

    @Test
    void rejectsAPackThatDoesNotListTheSelectedPart() throws Exception {
        assertThrows(Stm32MappingException.class, () -> Stm32SvdApplicator.applyRegisters(
            program, f103, "STM32C031C6T3", selection, TaskMonitor.DUMMY));
        assertNull(program.getMemory().getBlock(address(0x40010800L)));
    }

    @Test
    void bundledPacksFailClosedForShippedEntries() throws Exception {
        Stm32SvdApplicability applicability = Stm32SvdApplicability.load(APPLICABILITY,
            selection, ParserLimits.defaults(), CancellationToken.none());
        String previous = System.getProperty("embedra.projectDir");
        System.setProperty("embedra.projectDir", Path.of("").toAbsolutePath().toString());
        try {
            Stm32BundledPacks shipped = Stm32BundledPacks.load(
                applicability.requireEntry("STM32F103C8T6"), ParserLimits.defaults(),
                CancellationToken.none());
            assertTrue(shipped.forDevice("STM32F103").isPresent());
            Stm32BundledPacks deferred = Stm32BundledPacks.load(
                applicability.requireEntry("STM32H573IIK3Q"), ParserLimits.defaults(),
                CancellationToken.none());
            assertTrue(deferred.packs().isEmpty());
            var shippedExact = applicability.requireEntry("STM32F103C8T6");
            var notShipped = Stm32BundledPacks.load(
                new Stm32SvdApplicability.Entry(shippedExact.exactPart(),
                    shippedExact.family(), Stm32SvdApplicability.Status.EXACT_SVD_DEFERRED,
                    shippedExact.svdFiles(), null),
                ParserLimits.defaults(), CancellationToken.none());
            assertTrue(notShipped.packs().isEmpty());
            var exact = applicability.requireEntry("STM32F103C8T6");
            var source = exact.svdFiles().getFirst();
            var tamperedPin = new Stm32SvdApplicability.Entry(exact.exactPart(), exact.family(),
                Stm32SvdApplicability.Status.EXACT_SVD_SHIPPED,
                List.of(new Stm32SvdApplicability.SvdFile(source.deviceName(), source.path(),
                    "0".repeat(64), source.cpu())), null);
            assertThrows(IOException.class, () -> Stm32BundledPacks.load(tamperedPin,
                ParserLimits.defaults(), CancellationToken.none()));
        }
        finally {
            if (previous == null) {
                System.clearProperty("embedra.projectDir");
            }
            else {
                System.setProperty("embedra.projectDir", previous);
            }
        }
    }

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
}
