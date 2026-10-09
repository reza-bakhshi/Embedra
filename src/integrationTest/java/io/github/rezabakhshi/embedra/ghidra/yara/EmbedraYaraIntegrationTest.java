package io.github.rezabakhshi.embedra.ghidra.yara;

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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraYaraIntegrationTest {

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
        program = new ProgramDB("YARA Integration Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void appliesYaraMatchesAndPreservesUserArtifacts() throws Exception {
        int tx = program.startTransaction("Setup test memory");
        Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000000L);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // 1. ChaCha20 constant
        out.write("expand 32-byte k".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0, 0, 0, 0});

        // 2. SquashFS magic
        out.write("hsqs".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[64]);

        byte[] payload = out.toByteArray();
        MemoryBlock block = program.getMemory().createInitializedBlock(
                ".text", startAddr, payload.length, (byte) 0, TaskMonitor.DUMMY, false);
        block.putBytes(startAddr, payload);

        // Pre-existing user symbol and bookmark
        Address userSymbolAddr = startAddr.add(0x04);
        program.getSymbolTable().createLabel(userSymbolAddr, "user_custom_landmark", SourceType.USER_DEFINED);
        program.getBookmarkManager().setBookmark(
                userSymbolAddr, BookmarkType.NOTE, "User Notes", "Preserve this note");

        program.endTransaction(tx, true);

        // Run EmbedraYaraAnalyzer
        EmbedraYaraAnalyzer analyzer = new EmbedraYaraAnalyzer();
        MessageLog log = new MessageLog();
        boolean success = analyzer.added(program, new AddressSet(block.getStart(), block.getEnd()),
                TaskMonitor.DUMMY, log);
        assertTrue(success);

        // Verify bookmarks
        List<Bookmark> yaraBookmarks = new ArrayList<>();
        var bookmarkIter = program.getBookmarkManager().getBookmarksIterator(BookmarkType.INFO);
        while (bookmarkIter.hasNext()) {
            Bookmark bm = bookmarkIter.next();
            if (bm.getCategory().startsWith("Embedra YARA: ")) {
                yaraBookmarks.add(bm);
            }
        }

        assertFalse(yaraBookmarks.isEmpty(), "Should have created YARA bookmarks");
        boolean hasChaCha = false;
        boolean hasSquash = false;
        for (Bookmark bm : yaraBookmarks) {
            if (bm.getCategory().contains("ChaCha20_Constant")) {
                hasChaCha = true;
            }
            if (bm.getCategory().contains("SquashFS_Superblock")) {
                hasSquash = true;
            }
        }
        assertTrue(hasChaCha, "Should have ChaCha20 bookmark");
        assertTrue(hasSquash, "Should have SquashFS bookmark");

        // Verify comments
        String chachaComment = program.getListing().getComment(CommentType.EOL, startAddr);
        assertNotNull(chachaComment);
        assertTrue(chachaComment.contains("[YARA: ChaCha20_Constant]"));

        // Verify user landmarks preserved
        var sym = program.getSymbolTable().getPrimarySymbol(userSymbolAddr);
        assertNotNull(sym);
        assertEquals("user_custom_landmark", sym.getName());

        var userBookmarks = program.getBookmarkManager().getBookmarks(userSymbolAddr, BookmarkType.NOTE);
        assertEquals(1, userBookmarks.length);
        assertEquals("Preserve this note", userBookmarks[0].getComment());

        // Verify Program Options
        var options = program.getOptions(GhidraYaraApplicator.PROGRAM_OPTIONS_CATEGORY);
        assertTrue(options.getInt("Total Matches Count", 0) >= 2);
    }
}
