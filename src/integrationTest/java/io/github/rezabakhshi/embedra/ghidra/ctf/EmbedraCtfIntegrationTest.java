package io.github.rezabakhshi.embedra.ghidra.ctf;

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
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityCategory;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityType;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfSeverity;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraCtfIntegrationTest {
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
        program = new ProgramDB("CTF Analysis Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void appliesCtfFindingsAndPreservesUserArtifacts() throws Exception {
        int tx = program.startTransaction("Setup memory");
        Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000000L);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("https://ota.embedra.internal/v2\0".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0x00, 0x00});
        out.write("ssid=SmartMeterNet;password=SuperSecretWpaPass\0".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0x00, 0x00});
        out.write("flag{cortex_m3_firmware_flag_found}\0".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0x00, 0x00});
        out.write("0000180d-0000-1000-8000-00805f9b34fb\0".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0x00, 0x00});

        byte[] memBytes = out.toByteArray();
        MemoryBlock block = program.getMemory().createInitializedBlock(
                "FLASH", startAddr, memBytes.length, (byte) 0, TaskMonitor.DUMMY, false);
        block.putBytes(startAddr, memBytes);

        // Pre-existing user label and bookmark that must not be altered
        Address userMarkerAddr = startAddr.add(8L);
        program.getSymbolTable().createLabel(userMarkerAddr, "user_flag_checkpoint", SourceType.USER_DEFINED);
        program.getBookmarkManager().setBookmark(
                userMarkerAddr, BookmarkType.NOTE, "User Category", "User landmark");

        program.endTransaction(tx, true);

        // Run EmbedraCtfAnalyzer
        EmbedraCtfAnalyzer analyzer = new EmbedraCtfAnalyzer();
        MessageLog log = new MessageLog();
        boolean success = analyzer.added(program, new AddressSet(startAddr, startAddr.add(memBytes.length - 1)),
                TaskMonitor.DUMMY, log);

        assertTrue(success);

        // Verify bookmarks created for discovered findings
        List<Bookmark> findingsBookmarks = new ArrayList<>();
        var bookmarkIter = program.getBookmarkManager().getBookmarksIterator(BookmarkType.INFO);
        while (bookmarkIter.hasNext()) {
            Bookmark b = bookmarkIter.next();
            if (b.getCategory().startsWith(GhidraCtfApplicator.BOOKMARK_CATEGORY_PREFIX)) {
                findingsBookmarks.add(b);
            }
        }

        assertFalse(findingsBookmarks.isEmpty());
        assertTrue(findingsBookmarks.stream().anyMatch(b ->
                b.getCategory().equals(GhidraCtfApplicator.BOOKMARK_CATEGORY_PREFIX + "ENDPOINT")));
        assertTrue(findingsBookmarks.stream().anyMatch(b ->
                b.getCategory().equals(GhidraCtfApplicator.BOOKMARK_CATEGORY_PREFIX + "CREDENTIAL")));
        assertTrue(findingsBookmarks.stream().anyMatch(b ->
                b.getCategory().equals(GhidraCtfApplicator.BOOKMARK_CATEGORY_PREFIX + "FLAG")));
        assertTrue(findingsBookmarks.stream().anyMatch(b ->
                b.getCategory().equals(GhidraCtfApplicator.BOOKMARK_CATEGORY_PREFIX + "UUID")));

        // Verify zero secret leaking: unmasked password or flag must not appear in log
        String logMessages = log.toString();
        assertFalse(logMessages.contains("SuperSecretWpaPass"));
        assertFalse(logMessages.contains("cortex_m3_firmware_flag_found"));

        // Verify program options
        var options = program.getOptions(GhidraCtfApplicator.PROGRAM_OPTIONS_CATEGORY);
        assertTrue(options.getInt("Total Findings Count", 0) >= 4);
        assertTrue(options.getInt("Findings (FLAG)", 0) >= 1);
        assertTrue(options.getInt("Findings (CREDENTIAL)", 0) >= 1);
        assertTrue(options.getInt("Findings (ENDPOINT)", 0) >= 1);

        // Verify user landmark is completely preserved
        assertEquals("user_flag_checkpoint",
                program.getSymbolTable().getPrimarySymbol(userMarkerAddr).getName());
        Bookmark[] userBookmarks = program.getBookmarkManager().getBookmarks(userMarkerAddr);
        boolean foundUserBookmark = false;
        for (Bookmark b : userBookmarks) {
            if ("User Category".equals(b.getCategory()) && "User landmark".equals(b.getComment())) {
                foundUserBookmark = true;
                break;
            }
        }
        assertTrue(foundUserBookmark);
    }

    @Test
    void directApplicatorWorksIdempotently() throws Exception {
        int tx = program.startTransaction("Setup memory");
        Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08002000L);
        program.getMemory().createInitializedBlock(
                "RAM", startAddr, 1024, (byte) 0, TaskMonitor.DUMMY, false);
        program.endTransaction(tx, true);

        List<CtfEntity> entities = List.of(
                new CtfEntity(
                        "ent-1",
                        CtfEntityCategory.FLAG,
                        CtfEntityType.FLAG,
                        CtfSeverity.HIGH,
                        StringConfidence.CONFIRMED,
                        0x08002010L,
                        20,
                        "flag{direct_applicator}",
                        "Direct test flag",
                        true
                )
        );

        GhidraCtfApplicationReport report1 = GhidraCtfApplicator.apply(program, entities, TaskMonitor.DUMMY);
        assertEquals(1, report1.totalFindings());
        assertEquals(1, report1.bookmarksCreated());
        assertEquals(1, report1.commentsCreated());

        // Re-apply to verify idempotence
        GhidraCtfApplicationReport report2 = GhidraCtfApplicator.apply(program, entities, TaskMonitor.DUMMY);
        assertEquals(1, report2.totalFindings());

        // Verify comment is not duplicated
        Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08002010L);
        String comment = program.getListing().getComment(CommentType.EOL, target);
        assertNotNull(comment);
        assertTrue(comment.contains("[Finding: CTF Flag (HIGH)]"));
        assertFalse(comment.contains("direct_applicator")); // Must be masked
    }
}
