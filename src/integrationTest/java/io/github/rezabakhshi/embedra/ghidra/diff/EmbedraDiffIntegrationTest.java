package io.github.rezabakhshi.embedra.ghidra.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import io.github.rezabakhshi.embedra.analyzers.diff.DiffChangeKind;
import io.github.rezabakhshi.embedra.analyzers.diff.FirmwareWorkspaceDiff;
import io.github.rezabakhshi.embedra.analyzers.diff.FirmwareWorkspaceDiffEngine;
import io.github.rezabakhshi.embedra.analyzers.diff.WorkspaceSnapshot;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.io.File;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraDiffIntegrationTest {

    private static final Object CONSUMER = new Object();

    private ProgramDB sourceProgram;

    private ProgramDB targetProgram;

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                    new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),
                    configuration);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(
                new LanguageID("ARM:LE:32:Cortex"));
        var compilerSpec = language.getCompilerSpecByID(new CompilerSpecID("default"));

        sourceProgram = new ProgramDB("Firmware_v1_0", language, compilerSpec, CONSUMER);
        targetProgram = new ProgramDB("Firmware_v1_1", language, compilerSpec, CONSUMER);

        // Populate Source Program
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(sourceProgram, "Init Source Program")) {
            Address base = sourceProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000L);
            sourceProgram.getMemory().createInitializedBlock(".text", base, 0x1000, (byte) 0x90, null, false);
            Address ram = sourceProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x20000000L);
            sourceProgram.getMemory().createInitializedBlock(".data", ram, 0x400, (byte) 0, null, false);

            // Function
            var mainSet = new ghidra.program.model.address.AddressSet(base, base.add(63));
            sourceProgram.getFunctionManager().createFunction("main", base, mainSet, SourceType.USER_DEFINED);
            // Symbol
            sourceProgram.getSymbolTable().createLabel(ram, "g_status", SourceType.USER_DEFINED);
            // String (secret)
            Address strAddr = base.add(0x100);
            sourceProgram.getListing().createData(strAddr, new StringDataType(), 16);
            sourceProgram.getMemory().setBytes(strAddr, "apiKey=sec12345\0".getBytes());

            // Partition bookmark
            sourceProgram.getBookmarkManager().setBookmark(
                    base.add(0x200), BookmarkType.INFO, "Embedra Partition: factory", "factory app partition");

            tx.commit();
        }

        // Populate Target Program
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(targetProgram, "Init Target Program")) {
            Address base = targetProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000L);
            targetProgram.getMemory().createInitializedBlock(".text", base, 0x1200, (byte) 0x90, null, false);
            Address ram = targetProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x20000000L);
            targetProgram.getMemory().createInitializedBlock(".data", ram, 0x400, (byte) 0, null, false);

            // Function main modified, plus new function
            var mainSet = new ghidra.program.model.address.AddressSet(base, base.add(79));
            targetProgram.getFunctionManager().createFunction("main", base, mainSet, SourceType.USER_DEFINED);
            Address newFuncAddr = base.add(0x80);
            var otaSet = new ghidra.program.model.address.AddressSet(newFuncAddr, newFuncAddr.add(31));
            targetProgram.getFunctionManager().createFunction("ota_update", newFuncAddr, otaSet,
                    SourceType.USER_DEFINED);

            // Symbol moved
            targetProgram.getSymbolTable().createLabel(ram.add(4), "g_status", SourceType.USER_DEFINED);

            // String
            Address strAddr = base.add(0x100);
            targetProgram.getListing().createData(strAddr, new StringDataType(), 16);
            targetProgram.getMemory().setBytes(strAddr, "apiKey=sec12345\0".getBytes());

            // Partition bookmark
            targetProgram.getBookmarkManager().setBookmark(
                    base.add(0x200), BookmarkType.INFO, "Embedra Partition: factory", "factory app partition");

            tx.commit();
        }
    }

    @AfterEach
    void tearDown() {
        if (sourceProgram != null) {
            sourceProgram.release(CONSUMER);
        }
        if (targetProgram != null) {
            targetProgram.release(CONSUMER);
        }
    }

    @Test
    void extractsAndDiffsWorkspacesAccurately() throws Exception {
        GhidraWorkspaceDiffExtractor extractor = new GhidraWorkspaceDiffExtractor();
        WorkspaceSnapshot srcSnap = extractor.extract(sourceProgram);
        WorkspaceSnapshot tgtSnap = extractor.extract(targetProgram);

        assertEquals("Firmware_v1_0", srcSnap.workspaceName());
        assertEquals("Firmware_v1_1", tgtSnap.workspaceName());

        assertFalse(srcSnap.functions().isEmpty());
        assertFalse(tgtSnap.functions().isEmpty());
        assertFalse(srcSnap.symbols().isEmpty());
        assertFalse(tgtSnap.symbols().isEmpty());
        assertFalse(srcSnap.memoryBlocks().isEmpty());
        assertFalse(tgtSnap.memoryBlocks().isEmpty());
        assertFalse(srcSnap.metadata().isEmpty());

        FirmwareWorkspaceDiffEngine engine = new FirmwareWorkspaceDiffEngine();
        FirmwareWorkspaceDiff diff = engine.compare(srcSnap, tgtSnap);

        assertNotNull(diff);
        assertTrue(diff.totalDifferences() > 0);

        // main was modified (length 64 -> 80)
        var mainEntry = diff.functions().stream()
                .filter(f -> f.functionName().equals("main")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.MODIFIED, mainEntry.changeKind());

        // ota_update was added
        var otaEntry = diff.functions().stream()
                .filter(f -> f.functionName().equals("ota_update")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.ADDED, otaEntry.changeKind());

        // g_status was moved
        var symEntry = diff.symbols().stream()
                .filter(s -> s.symbolName().equals("g_status")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.MOVED, symEntry.changeKind());

        // .text was modified
        var textEntry = diff.memoryBlocks().stream()
                .filter(m -> m.blockName().equals(".text")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.MODIFIED, textEntry.changeKind());

        // .data was unchanged
        var dataEntry = diff.memoryBlocks().stream()
                .filter(m -> m.blockName().equals(".data")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.UNCHANGED, dataEntry.changeKind());
    }

    @Test
    void tableModelsPopulateAndFilterViews() throws Exception {
        GhidraWorkspaceDiffExtractor extractor = new GhidraWorkspaceDiffExtractor();
        WorkspaceSnapshot srcSnap = extractor.extract(sourceProgram);
        WorkspaceSnapshot tgtSnap = extractor.extract(targetProgram);
        FirmwareWorkspaceDiff diff = new FirmwareWorkspaceDiffEngine().compare(srcSnap, tgtSnap);

        // Check Function Table Model
        var funcModel = new DiffTableModels.FunctionTableModel();
        funcModel.setEntries(diff.functions());
        assertTrue(funcModel.getRowCount() >= 2);

        // Filter functions by text
        funcModel.setFilters(null, "ota");
        assertEquals(1, funcModel.getRowCount());
        assertEquals("ota_update", funcModel.getEntryAt(0).functionName());

        // Filter functions by change kind
        funcModel.setFilters(DiffChangeKind.MODIFIED, "");
        assertEquals(1, funcModel.getRowCount());
        assertEquals("main", funcModel.getEntryAt(0).functionName());

        // Clear filters
        funcModel.setFilters(null, "");
        assertTrue(funcModel.getRowCount() >= 2);

        // Check Symbol Table Model
        var symModel = new DiffTableModels.SymbolTableModel();
        symModel.setEntries(diff.symbols());
        assertTrue(symModel.getRowCount() >= 1);

        // Check Memory Table Model
        var memModel = new DiffTableModels.MemoryTableModel();
        memModel.setEntries(diff.memoryBlocks());
        assertEquals(2, memModel.getRowCount());

        // Check String Table Model and Secret Redaction
        var strModel = new DiffTableModels.StringTableModel();
        strModel.setEntries(diff.strings());
        if (strModel.getRowCount() > 0) {
            strModel.setRedactSecrets(true);
            assertEquals("[REDACTED_SECRET]", strModel.getValueAt(0, 1));
            strModel.setRedactSecrets(false);
            assertEquals("apiKey=sec12345", strModel.getValueAt(0, 1));
        }

        // Verify export generation
        String json = diff.toJson(true);
        assertTrue(json.contains("[REDACTED_SECRET]"));
        String md = diff.toMarkdown(true);
        assertTrue(md.contains("# Embedra Firmware Workspace Diff Report"));
        String sarif = diff.toSarif(true);
        assertTrue(sarif.contains("\"version\": \"2.1.0\""));
    }
}
