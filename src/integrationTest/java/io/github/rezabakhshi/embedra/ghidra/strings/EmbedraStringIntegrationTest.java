package io.github.rezabakhshi.embedra.ghidra.strings;

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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.analyzers.strings.StringProvenance;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraStringIntegrationTest {
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
        program = new ProgramDB("String Analysis Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void appliesStaticAndStackStringAnnotationsIdempotently() throws Exception {
        int tx = program.startTransaction("Setup memory");
        Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000000L);

        // Populate memory with static strings
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("Banner: STM32 Bootloader v2.1\0".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0x00, 0x00});
        out.write("UTF-16LE System Title\0".getBytes(StandardCharsets.UTF_16LE));
        out.write(new byte[]{0x00, 0x00});
        out.write("Multilingual \u00e9\u00e8\u00ea \u4e2d\u6587\0".getBytes(StandardCharsets.UTF_8));
        out.write(new byte[]{0x00, 0x00});

        byte[] memBytes = out.toByteArray();
        MemoryBlock block = program.getMemory().createInitializedBlock(
                "FLASH", startAddr, memBytes.length, (byte) 0, TaskMonitor.DUMMY, false);
        block.putBytes(startAddr, memBytes);

        // Pre-existing user symbol and bookmark that must not be destroyed
        Address userSymbolAddr = startAddr.add(10L);
        program.getSymbolTable().createLabel(userSymbolAddr, "user_special_marker", SourceType.USER_DEFINED);
        program.getBookmarkManager().setBookmark(
                userSymbolAddr, BookmarkType.NOTE, "User Category", "User-defined note");

        program.endTransaction(tx, true);

        // Prepare extracted strings and recovered stack strings
        List<ExtractedString> staticStrings = List.of(
                new ExtractedString(0x08000000L, 30, StringEncoding.ASCII,
                        "Banner: STM32 Bootloader v2.1", StringConfidence.CONFIRMED,
                        StringProvenance.STATIC_LITERAL, true),
                new ExtractedString(0x08000020L, 44, StringEncoding.UTF_16LE,
                        "UTF-16LE System Title", StringConfidence.CONFIRMED,
                        StringProvenance.STATIC_LITERAL, true),
                new ExtractedString(0x08000050L, 25, StringEncoding.UTF_8,
                        "Multilingual \u00e9\u00e8\u00ea \u4e2d\u6587", StringConfidence.CONFIRMED,
                        StringProvenance.STATIC_LITERAL, true)
        );

        List<RecoveredStackString> stackStrings = List.of(
                new RecoveredStackString(0x08000000L, 0x10L, "FLAG{stack_recovered_token}",
                        StringEncoding.ASCII, StringConfidence.CONFIRMED,
                        0x08000004L, 0x08000018L, 6)
        );

        // Apply via GhidraStringApplicator
        GhidraStringApplicationReport report1 = GhidraStringApplicator.apply(
                program, staticStrings, stackStrings, TaskMonitor.DUMMY);

        assertEquals(3, report1.staticStringsCount());
        assertEquals(1, report1.stackStringsCount());
        assertEquals(4, report1.totalStringsCount());
        assertEquals(1, report1.asciiCount());
        assertEquals(1, report1.utf16LeCount());
        assertEquals(1, report1.utf8Count());

        // Verify Program Options
        var options = program.getOptions(GhidraStringApplicator.PROGRAM_OPTIONS_CATEGORY);
        assertEquals(1, options.getInt("ASCII Strings Count", -1));
        assertEquals(1, options.getInt("UTF-8 Strings Count", -1));
        assertEquals(1, options.getInt("UTF-16LE Strings Count", -1));
        assertEquals(3, options.getInt("Total Static Strings Count", -1));
        assertEquals(1, options.getInt("Recovered Stack Strings Count", -1));
        assertEquals(4, options.getInt("Total Strings Count", -1));

        // Verify Bookmarks
        List<Bookmark> staticBookmarks = new ArrayList<>();
        program.getBookmarkManager().getBookmarksIterator(BookmarkType.INFO).forEachRemaining(b -> {
            if (GhidraStringApplicator.BOOKMARK_CATEGORY_STATIC.equals(b.getCategory())) {
                staticBookmarks.add(b);
            }
        });
        assertEquals(3, staticBookmarks.size());

        List<Bookmark> stackBookmarks = new ArrayList<>();
        program.getBookmarkManager().getBookmarksIterator(BookmarkType.INFO).forEachRemaining(b -> {
            if (GhidraStringApplicator.BOOKMARK_CATEGORY_STACK.equals(b.getCategory())) {
                stackBookmarks.add(b);
            }
        });
        assertEquals(1, stackBookmarks.size());
        assertTrue(stackBookmarks.get(0).getComment().contains("FLAG{stack_recovered_token}"));

        // Verify Comments
        String eolComment = program.getListing().getComment(CommentType.EOL, startAddr);
        assertNotNull(eolComment);
        assertTrue(eolComment.contains("Banner: STM32 Bootloader v2.1"));

        // Verify user symbols and bookmarks were preserved intact
        assertNotNull(program.getSymbolTable().getPrimarySymbol(userSymbolAddr));
        assertEquals("user_special_marker", program.getSymbolTable().getPrimarySymbol(userSymbolAddr).getName());
        Bookmark userBm = program.getBookmarkManager().getBookmark(userSymbolAddr, BookmarkType.NOTE, "User Category");
        assertNotNull(userBm);
        assertEquals("User-defined note", userBm.getComment());

        // Idempotence: re-apply must succeed without duplicating
        GhidraStringApplicationReport report2 = GhidraStringApplicator.apply(
                program, staticStrings, stackStrings, TaskMonitor.DUMMY);
        assertEquals(4, report2.totalStringsCount());
    }

    @Test
    void runsEmbedraStringAnalyzerOverProgram() throws Exception {
        int tx = program.startTransaction("Setup memory with strings");
        Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000000L);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("Hardware-ID: RevB-2026\0".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0x00, 0x00});

        byte[] memBytes = out.toByteArray();
        MemoryBlock block = program.getMemory().createInitializedBlock(
                "FLASH", startAddr, memBytes.length, (byte) 0, TaskMonitor.DUMMY, false);
        block.putBytes(startAddr, memBytes);

        program.endTransaction(tx, true);

        EmbedraStringAnalyzer analyzer = new EmbedraStringAnalyzer();
        assertTrue(analyzer.canAnalyze(program));

        MessageLog log = new MessageLog();
        AddressSet set = new AddressSet(startAddr, startAddr.add(memBytes.length - 1));
        boolean analyzed = analyzer.added(program, set, TaskMonitor.DUMMY, log);

        assertTrue(analyzed);
        var options = program.getOptions(GhidraStringApplicator.PROGRAM_OPTIONS_CATEGORY);
        assertTrue(options.getInt("Total Static Strings Count", 0) >= 1);
    }
}
