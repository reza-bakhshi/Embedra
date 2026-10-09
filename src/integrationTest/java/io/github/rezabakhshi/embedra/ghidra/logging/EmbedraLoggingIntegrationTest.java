package io.github.rezabakhshi.embedra.ghidra.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.logging.DiagnosticLogLevel;
import io.github.rezabakhshi.embedra.analyzers.logging.FormatStringDescriptor;
import io.github.rezabakhshi.embedra.analyzers.logging.LoggingCallSite;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraLoggingIntegrationTest {
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
        program = new ProgramDB("Logging Analysis Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void appliesLoggingAndAssertAnnotationsIdempotently() throws Exception {
        int tx = program.startTransaction("Setup memory");
        Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000000L);

        byte[] memBytes = new byte[1024];
        MemoryBlock block = program.getMemory().createInitializedBlock(
                "FLASH", startAddr, memBytes.length, (byte) 0, TaskMonitor.DUMMY, false);
        block.putBytes(startAddr, memBytes);

        // Pre-existing user symbol and bookmark that must not be destroyed
        Address userSymbolAddr = startAddr.add(10L);
        program.getSymbolTable().createLabel(userSymbolAddr, "user_function_marker", SourceType.USER_DEFINED);
        program.getBookmarkManager().setBookmark(
                userSymbolAddr, BookmarkType.NOTE, "User Note Category", "Do not alter this note");

        program.endTransaction(tx, true);

        // Prepare test logging call sites
        LoggingCallSite infoSite = new LoggingCallSite(
                0x08000020L,
                0x08000500L,
                "printf",
                DiagnosticLogLevel.INFO,
                FormatStringDescriptor.plain("System boot: code=%d\n"),
                Map.of(),
                "CONFIRMED",
                "Info logging call site"
        );

        LoggingCallSite errorSite = new LoggingCallSite(
                0x08000040L,
                0x08000520L,
                "ESP_LOGE",
                DiagnosticLogLevel.ERROR,
                FormatStringDescriptor.plain("[E] Sensor read failed: %d\n"),
                Map.of("tag", "SENSOR"),
                "CONFIRMED",
                "Error logging call site"
        );

        LoggingCallSite assertSite = new LoggingCallSite(
                0x08000060L,
                0x08000540L,
                "__assert_func",
                DiagnosticLogLevel.ASSERT,
                FormatStringDescriptor.empty(),
                Map.of("file", "driver.c", "line", "105", "expression", "buf != NULL"),
                "CONFIRMED",
                "Assert call site"
        );

        LoggingCallSite panicSite = new LoggingCallSite(
                0x08000080L,
                0x08000560L,
                "panic",
                DiagnosticLogLevel.PANIC,
                FormatStringDescriptor.empty(),
                Map.of("message", "Kernel stack overflow"),
                "CONFIRMED",
                "Panic call site"
        );

        List<LoggingCallSite> callSites = List.of(infoSite, errorSite, assertSite, panicSite);

        // Apply via GhidraLoggingApplicator
        GhidraLoggingApplicationReport report = GhidraLoggingApplicator.apply(
                program, callSites, TaskMonitor.DUMMY);

        assertEquals(4, report.totalCallSites());
        assertEquals(1, report.infoCount());
        assertEquals(1, report.errorCount());
        assertEquals(1, report.assertCount());
        assertEquals(1, report.panicCount());
        assertEquals(4, report.bookmarksCreated());
        assertEquals(4, report.commentsCreated());

        // Verify Program Options
        var options = program.getOptions(GhidraLoggingApplicator.PROGRAM_OPTIONS_CATEGORY);
        assertEquals(4, options.getInt("Total Logging Call Sites", -1));
        assertEquals(1, options.getInt("Info Count", -1));
        assertEquals(1, options.getInt("Error Count", -1));
        assertEquals(1, options.getInt("Assert Count", -1));
        assertEquals(1, options.getInt("Panic Count", -1));

        // Verify Bookmarks
        List<Bookmark> loggingBookmarks = new ArrayList<>();
        program.getBookmarkManager().getBookmarksIterator(BookmarkType.INFO).forEachRemaining(b -> {
            if (b.getCategory().startsWith(GhidraLoggingApplicator.BOOKMARK_PREFIX)) {
                loggingBookmarks.add(b);
            }
        });
        assertEquals(4, loggingBookmarks.size());

        // Verify Comments
        Address infoAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000020L);
        String eolComment = program.getListing().getComment(CommentType.EOL, infoAddr);
        assertNotNull(eolComment);
        assertTrue(eolComment.contains("[Log: INFO] \"System boot: code=%d\n\""));

        Address assertAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000060L);
        String assertComment = program.getListing().getComment(CommentType.EOL, assertAddr);
        assertNotNull(assertComment);
        assertTrue(assertComment.contains("assert(buf != NULL) (driver.c:105)"));

        // Verify user symbols and bookmarks were preserved intact
        assertNotNull(program.getSymbolTable().getPrimarySymbol(userSymbolAddr));
        assertEquals("user_function_marker",
                program.getSymbolTable().getPrimarySymbol(userSymbolAddr).getName());

        Bookmark[] userBookmarks = program.getBookmarkManager().getBookmarks(userSymbolAddr);
        assertEquals(1, userBookmarks.length);
        assertEquals("User Note Category", userBookmarks[0].getCategory());
        assertEquals("Do not alter this note", userBookmarks[0].getComment());

        // Test Idempotence: re-applying should succeed and preserve counts
        GhidraLoggingApplicationReport report2 = GhidraLoggingApplicator.apply(
                program, callSites, TaskMonitor.DUMMY);
        assertEquals(4, report2.totalCallSites());
    }

    @Test
    void analyzerExecutesWithoutCrashingOnEmptyProgram() throws Exception {
        EmbedraLoggingAnalyzer analyzer = new EmbedraLoggingAnalyzer();
        assertTrue(analyzer.canAnalyze(program));

        MessageLog log = new MessageLog();
        boolean success = analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, log);
        assertTrue(success);
    }
}
