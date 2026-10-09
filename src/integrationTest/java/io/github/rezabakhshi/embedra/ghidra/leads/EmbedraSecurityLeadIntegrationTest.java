package io.github.rezabakhshi.embedra.ghidra.leads;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.leads.HeuristicFactor;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadCategory;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadConfidence;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLeadsReport;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraSecurityLeadIntegrationTest {
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
        program = new ProgramDB("Security Leads Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void appliesSecurityLeadAnnotationsIdempotently() throws Exception {
        int tx = program.startTransaction("Setup memory");
        Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000000L);

        byte[] memBytes = new byte[1024];
        MemoryBlock block = program.getMemory().createInitializedBlock(
                "FLASH", startAddr, memBytes.length, (byte) 0, TaskMonitor.DUMMY, false);
        block.putBytes(startAddr, memBytes);

        // Pre-existing user symbol and note bookmark that must not be destroyed
        Address userSymbolAddr = startAddr.add(10L);
        program.getSymbolTable().createLabel(userSymbolAddr, "critical_user_label", SourceType.USER_DEFINED);
        program.getBookmarkManager().setBookmark(
                userSymbolAddr, BookmarkType.NOTE, "User Note Category", "Custom note text");

        program.endTransaction(tx, true);

        // Prepare test leads across categories
        SecurityLead cmpLead = new SecurityLead(
                "LEAD-CMP-0001",
                LeadCategory.PASSWORD_TOKEN_COMPARISON,
                LeadConfidence.HIGH,
                0.90,
                LeadSeverity.CRITICAL,
                0x08000020L,
                "strcmp",
                "admin_pass_123",
                "Candidate password comparison against hardcoded credential",
                List.of(HeuristicFactor.of("HARDCODED_SECRET", "Hardcoded credential", 0.5)),
                Map.of(),
                true
        );

        SecurityLead authLead = new SecurityLead(
                "LEAD-AUTH-0001",
                LeadCategory.AUTHORIZATION_BRANCH,
                LeadConfidence.HIGH,
                0.85,
                LeadSeverity.HIGH,
                0x08000024L,
                null,
                "cbz",
                "Candidate authorization branch testing password result",
                List.of(HeuristicFactor.of("BRANCH_CHECK", "Gated execution branch", 0.5)),
                Map.of(),
                false
        );

        SecurityLead cmdLead = new SecurityLead(
                "LEAD-CMD-0001",
                LeadCategory.DEBUG_COMMAND,
                LeadConfidence.HIGH,
                0.90,
                LeadSeverity.HIGH,
                0x08000040L,
                null,
                "root",
                "Candidate debug command root in CLI table",
                List.of(HeuristicFactor.of("COMMAND_TABLE", "Command table entry", 0.5)),
                Map.of(),
                false
        );

        SecurityLead shellLead = new SecurityLead(
                "LEAD-SHL-0001",
                LeadCategory.DEBUG_SHELL,
                LeadConfidence.MEDIUM,
                0.60,
                LeadSeverity.MEDIUM,
                0x08000060L,
                null,
                "shell> ",
                "Candidate interactive debug shell prompt",
                List.of(HeuristicFactor.of("PROMPT_PATTERN", "Shell prompt pattern", 0.4)),
                Map.of(),
                false
        );

        SecurityLead otaLead = new SecurityLead(
                "LEAD-OTA-0001",
                LeadCategory.OTA_ENDPOINT,
                LeadConfidence.HIGH,
                0.80,
                LeadSeverity.HIGH,
                0x08000080L,
                "esp_https_ota",
                "https://ota.local/firmware.bin",
                "Candidate OTA firmware update URL",
                List.of(HeuristicFactor.of("OTA_URL", "OTA URL endpoint", 0.5)),
                Map.of(),
                false
        );

        SecurityLeadsReport report = new SecurityLeadsReport(
                List.of(cmpLead, authLead, cmdLead, shellLead, otaLead));

        // Apply leads via GhidraSecurityLeadApplicator
        GhidraSecurityLeadApplicationReport appReport = GhidraSecurityLeadApplicator.apply(
                program, report, TaskMonitor.DUMMY);

        assertEquals(5, appReport.totalLeads());
        assertEquals(1, appReport.passwordComparisons());
        assertEquals(1, appReport.authorizationBranches());
        assertEquals(1, appReport.debugCommands());
        assertEquals(1, appReport.debugShells());
        assertEquals(1, appReport.otaEndpoints());
        assertEquals(4, appReport.highConfidenceLeads());
        assertEquals(5, appReport.bookmarksCreated());
        assertEquals(5, appReport.commentsCreated());

        // Verify Program Options
        var options = program.getOptions(GhidraSecurityLeadApplicator.PROGRAM_OPTIONS_CATEGORY);
        assertEquals(5, options.getInt("Total Security Leads", -1));
        assertEquals(4, options.getInt("High Confidence Leads", -1));
        assertEquals(1, options.getInt("Password Comparisons", -1));
        assertEquals(1, options.getInt("Authorization Branches", -1));
        assertEquals(1, options.getInt("Debug Commands", -1));
        assertEquals(1, options.getInt("Debug Shells", -1));
        assertEquals(1, options.getInt("OTA Endpoints", -1));

        // Verify Bookmarks created under "Embedra Lead: *"
        List<Bookmark> leadBookmarks = new ArrayList<>();
        program.getBookmarkManager().getBookmarksIterator(BookmarkType.INFO).forEachRemaining(b -> {
            if (b.getCategory().startsWith(GhidraSecurityLeadApplicator.BOOKMARK_PREFIX)) {
                leadBookmarks.add(b);
            }
        });
        assertEquals(5, leadBookmarks.size());

        // Verify that candidate secret target was masked in the bookmark
        Bookmark cmpBookmark = leadBookmarks.stream()
                .filter(b -> b.getCategory().contains("Password"))
                .findFirst()
                .orElseThrow();
        assertTrue(cmpBookmark.getComment().contains("[REDACTED_SECRET]"));

        // Verify Comments created
        Address cmpAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000020L);
        String cmpComment = program.getListing().getComment(CommentType.EOL, cmpAddr);
        assertNotNull(cmpComment);
        assertTrue(cmpComment.contains("[Lead: Password / Token Comparison (High)]"));

        // Verify user symbols and bookmarks were preserved intact
        assertNotNull(program.getSymbolTable().getPrimarySymbol(userSymbolAddr));
        assertEquals("critical_user_label",
                program.getSymbolTable().getPrimarySymbol(userSymbolAddr).getName());

        Bookmark[] userBookmarks = program.getBookmarkManager().getBookmarks(userSymbolAddr);
        assertEquals(1, userBookmarks.length);
        assertEquals("User Note Category", userBookmarks[0].getCategory());
        assertEquals("Custom note text", userBookmarks[0].getComment());

        // Verify Idempotence
        GhidraSecurityLeadApplicationReport appReport2 = GhidraSecurityLeadApplicator.apply(
                program, report, TaskMonitor.DUMMY);
        assertEquals(5, appReport2.totalLeads());
        assertEquals(0, appReport2.bookmarksCreated(), "Bookmarks should not be duplicated");
    }

    @Test
    void analyzerExecutesWithoutCrashingOnEmptyProgram() throws Exception {
        EmbedraSecurityLeadAnalyzer analyzer = new EmbedraSecurityLeadAnalyzer();
        assertTrue(analyzer.canAnalyze(program));

        MessageLog log = new MessageLog();
        boolean success = analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, log);
        assertTrue(success);
    }
}
