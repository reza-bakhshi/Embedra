package io.github.rezabakhshi.embedra.ghidra.findings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefaultLanguageService;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFinding;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.io.File;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraFindingsIntegrationTest {

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
        program = new ProgramDB("Findings Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Create Test Memory")) {
            Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000L);
            program.getMemory().createInitializedBlock(
                    ".text", start, 0x10000, (byte) 0, null, false);
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
    void extractsFindingsFromBookmarksAndSynchronizesSuppression() throws Exception {
        Address addr1 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000L);
        Address addr2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x3000L);
        Address addr3 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x4000L);
        Address addr4 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x5000L);

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Add Bookmarks")) {
            var bmManager = program.getBookmarkManager();
            bmManager.setBookmark(addr1, BookmarkType.INFO, "Embedra Findings: FLAG_LITERAL",
                    "CTF{found_flag} [CONFIRMED]");
            bmManager.setBookmark(addr2, BookmarkType.INFO, "Embedra Crypto: AES_KEY_MATERIAL",
                    "128-bit key schedule");
            bmManager.setBookmark(addr3, BookmarkType.INFO, "Embedra Logging: PANIC",
                    "Kernel panic in driver.c:120");
            bmManager.setBookmark(addr4, BookmarkType.INFO, "Embedra Lead: PASSWORD_CHECK",
                    "Hardcoded credential comparison");
            tx.commit();
        }

        List<UnifiedFinding> findings = GhidraFindingBookmarkSynchronizer.extractFindingsFromBookmarks(program);
        assertEquals(4, findings.size());

        UnifiedFinding ctfFinding = findings.stream()
                .filter(f -> f.category() == FindingCategory.CTF_ENTITY)
                .findFirst().orElseThrow();
        assertEquals(0x2000L, ctfFinding.address());
        assertFalse(ctfFinding.suppressed());

        UnifiedFinding cryptoFinding = findings.stream()
                .filter(f -> f.category() == FindingCategory.CRYPTOGRAPHY)
                .findFirst().orElseThrow();
        assertEquals(FindingSeverity.CRITICAL, cryptoFinding.severity());

        // Test suppressing finding 1
        boolean suppressed = GhidraFindingBookmarkSynchronizer.setFindingSuppression(
                program, ctfFinding, true, "Known test flag");
        assertTrue(suppressed);

        List<UnifiedFinding> updated = GhidraFindingBookmarkSynchronizer.extractFindingsFromBookmarks(program);
        UnifiedFinding updatedCtf = updated.stream()
                .filter(f -> f.category() == FindingCategory.CTF_ENTITY)
                .findFirst().orElseThrow();
        assertTrue(updatedCtf.suppressed());
        assertEquals("Known test flag", updatedCtf.suppressionReason());

        // Test unsuppressing
        boolean unsuppressed = GhidraFindingBookmarkSynchronizer.setFindingSuppression(
                program, updatedCtf, false, null);
        assertTrue(unsuppressed);

        List<UnifiedFinding> unsuppressedList = GhidraFindingBookmarkSynchronizer.extractFindingsFromBookmarks(program);
        UnifiedFinding unsuppressedCtf = unsuppressedList.stream()
                .filter(f -> f.category() == FindingCategory.CTF_ENTITY)
                .findFirst().orElseThrow();
        assertFalse(unsuppressedCtf.suppressed());
    }

    @Test
    void tableModelFiltersAndRedactsSecrets() {
        FindingsTableModel model = new FindingsTableModel();

        UnifiedFinding f1 = new UnifiedFinding(
                "F1", FindingCategory.CTF_ENTITY, "FLAG", FindingSeverity.HIGH,
                io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence.CONFIRMED,
                0.9, "ARM", 0x1000L, 10, "FLAG{secret}", "Secret flag", true, false, null, java.util.Map.of());

        UnifiedFinding f2 = new UnifiedFinding(
                "F2", FindingCategory.CRYPTOGRAPHY, "CRC", FindingSeverity.LOW,
                io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence.CONFIRMED,
                0.9, "ARM", 0x2000L, 4, "crc32", "CRC table", false, true, "Suppressed", java.util.Map.of());

        model.setFindings(List.of(f1, f2));
        assertEquals(2, model.getRowCount());

        // Secret redaction test
        assertEquals("[REDACTED_SECRET]", model.getValueAt(0, FindingsTableModel.COL_TARGET));
        model.setRedactSecrets(false);
        assertEquals("FLAG{secret}", model.getValueAt(0, FindingsTableModel.COL_TARGET));

        // Category filter
        model.setCategoryFilter(FindingCategory.CRYPTOGRAPHY);
        assertEquals(1, model.getRowCount());
        assertEquals("F2", model.getFindingAt(0).id());

        // Clear category filter
        model.setCategoryFilter(null);
        assertEquals(2, model.getRowCount());

        // Suppression filter
        model.setShowSuppressed(false);
        assertEquals(1, model.getRowCount());
        assertEquals("F1", model.getFindingAt(0).id());

        // Text filter
        model.setShowSuppressed(true);
        model.setTextFilter("flag");
        assertEquals(1, model.getRowCount());
        assertEquals("F1", model.getFindingAt(0).id());
    }
}
