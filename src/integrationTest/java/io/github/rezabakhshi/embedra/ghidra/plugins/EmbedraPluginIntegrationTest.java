package io.github.rezabakhshi.embedra.ghidra.plugins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFinding;
import io.github.rezabakhshi.embedra.analyzers.plugins.DeclarativeMatcherType;
import io.github.rezabakhshi.embedra.analyzers.plugins.DeclarativeRuleDefinition;
import io.github.rezabakhshi.embedra.analyzers.plugins.DeclarativeScannerPlugin;
import io.github.rezabakhshi.embedra.analyzers.plugins.PluginCapability;
import io.github.rezabakhshi.embedra.analyzers.plugins.PluginResourceBudget;
import io.github.rezabakhshi.embedra.analyzers.plugins.PluginType;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginManifest;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginRegistry;
import io.github.rezabakhshi.embedra.ghidra.findings.GhidraFindingBookmarkSynchronizer;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.io.File;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraPluginIntegrationTest {

    private static final Object CONSUMER = new Object();

    private ProgramDB program;

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
        program = new ProgramDB("Plugin Test Program", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Initialize Memory")) {
            Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000L);
            program.getMemory().createInitializedBlock(".text", start, 0x1000, (byte) 0, null, false);

            // Write target pattern into memory: "FLAG{PLUGIN_CTF_SUCCESS}"
            byte[] flagBytes = "FLAG{PLUGIN_CTF_SUCCESS}\0".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            program.getMemory().setBytes(start, flagBytes);

            program.getListing().createData(start, new StringDataType(), flagBytes.length);
            tx.commit();
        }
    }

    @AfterEach
    void tearDown() {
        if (program != null) {
            program.release(CONSUMER);
        }
    }

    @Test
    void runsPluginAnalyzerAndCreatesBookmarks() throws Exception {
        ScannerPluginRegistry registry = new ScannerPluginRegistry();

        DeclarativeRuleDefinition rule = new DeclarativeRuleDefinition(
                "flag-matcher",
                "Matches CTF flags",
                DeclarativeMatcherType.REGEX,
                "FLAG\\{[A-Z0-9_]+\\}",
                FindingSeverity.HIGH,
                FindingConfidence.CONFIRMED,
                1.0,
                true,
                FindingCategory.CUSTOM_PLUGIN,
                "FLAG",
                null,
                null
        );

        ScannerPluginManifest manifest = new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                "ctf.flag-scanner",
                "Flag Scanner",
                "1.0.0",
                "Embedra",
                "Discovers CTF flags",
                PluginType.DECLARATIVE_RULE,
                "ALL",
                null,
                Set.of(PluginCapability.STRING_SCAN, PluginCapability.BYTE_SCAN),
                PluginResourceBudget.defaults(),
                List.of(rule)
        );

        registry.register(new DeclarativeScannerPlugin(manifest));

        EmbedraPluginAnalyzer analyzer = new EmbedraPluginAnalyzer(registry);
        assertTrue(analyzer.canAnalyze(program));

        MessageLog log = new MessageLog();
        boolean result = analyzer.added(program, null, TaskMonitor.DUMMY, log);
        assertTrue(result);

        // Verify bookmark was created
        Bookmark[] bookmarks = program.getBookmarkManager().getBookmarks(
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000L),
                BookmarkType.INFO
        );

        assertEquals(1, bookmarks.length);
        assertEquals("Embedra Plugin: ctf.flag-scanner", bookmarks[0].getCategory());
        assertTrue(bookmarks[0].getComment().contains("Matches CTF flags"));

        // Verify extraction via GhidraFindingBookmarkSynchronizer
        List<UnifiedFinding> findings = GhidraFindingBookmarkSynchronizer.extractFindingsFromBookmarks(program);
        assertFalse(findings.isEmpty());
        UnifiedFinding uf = findings.get(0);
        assertEquals(FindingCategory.CUSTOM_PLUGIN, uf.category());
        assertEquals("ctf.flag-scanner", uf.subcategory());
        assertEquals(0x1000L, uf.address());

        // Verify program options
        var opts = program.getOptions(GhidraPluginApplicator.PROGRAM_OPTIONS_CATEGORY);
        assertEquals(1, opts.getInt("Total Plugin Findings", 0));
        assertEquals(1, opts.getInt("Bookmarks Created", 0));
    }
}
