package io.github.rezabakhshi.embedra.ghidra.crypto;

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
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraCryptoIntegrationTest {

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
        program = new ProgramDB("Crypto Analysis Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void appliesCryptoFindingsAndPreservesUserArtifacts() throws Exception {
        int tx = program.startTransaction("Setup crypto memory");
        Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08000000L);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // 1. ChaCha20 constant
        out.write("expand 32-byte k".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0, 0, 0, 0});

        // 2. AES S-box (64 bytes prefix)
        byte[] aesSboxSlice = new byte[] {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
            (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
            (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0,
            (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
            (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc,
            (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
            (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a,
            (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75
        };
        out.write(aesSboxSlice);
        out.write(new byte[]{0, 0, 0, 0});

        // 3. Candidate 128-bit key
        HexFormat hex = HexFormat.of();
        byte[] key16 = hex.parseHex("4a2f8b91c0e357d629a8f413b5e2786d");
        out.write(key16);
        out.write(new byte[]{0, 0, 0, 0});

        // 4. Base64 alphabet table (strict non-crypto)
        out.write(("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz0123456789+/").getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[]{0, 0, 0, 0});

        // 5. mbed TLS AES-128 function signature pattern (AN-011)
        byte[] mbedAes = hex.parseHex("2de9f04f85b0aa90");
        out.write(mbedAes);
        out.write(new byte[]{0, 0, 0, 0});

        byte[] memBytes = out.toByteArray();
        MemoryBlock block = program.getMemory().createInitializedBlock(
                "FLASH", startAddr, memBytes.length, (byte) 0, TaskMonitor.DUMMY, false);
        block.putBytes(startAddr, memBytes);

        // Pre-existing user label and bookmark that must not be altered
        Address userMarkerAddr = startAddr.add(8L);
        program.getSymbolTable().createLabel(userMarkerAddr, "user_crypto_checkpoint", SourceType.USER_DEFINED);
        program.getBookmarkManager().setBookmark(
                userMarkerAddr, BookmarkType.NOTE, "User Note", "User checkpoint");

        program.endTransaction(tx, true);

        // Run EmbedraCryptoAnalyzer
        EmbedraCryptoAnalyzer analyzer = new EmbedraCryptoAnalyzer();
        MessageLog log = new MessageLog();
        boolean success = analyzer.added(program, new AddressSet(startAddr, startAddr.add(memBytes.length - 1)),
                TaskMonitor.DUMMY, log);

        assertTrue(success, "EmbedraCryptoAnalyzer must return true on completion");

        // Verify bookmarks under Embedra Crypto: *
        List<Bookmark> cryptoBookmarks = new ArrayList<>();
        var bookmarkIter = program.getBookmarkManager().getBookmarksIterator();
        while (bookmarkIter.hasNext()) {
            Bookmark bm = bookmarkIter.next();
            if (bm.getCategory().startsWith(GhidraCryptoApplicator.BOOKMARK_CATEGORY_PREFIX)) {
                cryptoBookmarks.add(bm);
            }
        }

        assertFalse(cryptoBookmarks.isEmpty(), "Bookmarks must be created for crypto findings");
        assertTrue(cryptoBookmarks.stream().anyMatch(bm ->
                bm.getCategory().equals("Embedra Crypto: CIPHER_SYMMETRIC")),
                "Must have bookmark for CIPHER_SYMMETRIC");
        assertTrue(cryptoBookmarks.stream().anyMatch(bm ->
                bm.getCategory().equals("Embedra Crypto: ENCODING_OR_COMPRESSION")),
                "Must have bookmark for ENCODING_OR_COMPRESSION");
        assertTrue(cryptoBookmarks.stream().anyMatch(bm ->
                bm.getComment().contains("mbed TLS")),
                "Must have bookmark mentioning mbed TLS from signature matching");

        // Verify program options under Embedra Crypto Analysis
        var options = program.getOptions(GhidraCryptoApplicator.PROGRAM_OPTIONS_CATEGORY);
        int totalFindings = options.getInt("Total Findings Count", 0);
        assertTrue(totalFindings >= 3, "Expected at least 3 findings recorded in options, got: " + totalFindings);
        assertTrue(options.getInt("Findings (" + CryptoCategory.CIPHER_SYMMETRIC.name() + ")", 0) >= 2);
        assertTrue(options.getInt("Findings (" + CryptoCategory.ENCODING_OR_COMPRESSION.name() + ")", 0) >= 1);

        // Verify non-destructive EOL comments
        String comment = program.getListing().getComment(CommentType.EOL, startAddr);
        assertNotNull(comment);
        assertTrue(comment.contains("[Crypto: ChaCha20"), "Comment must mention ChaCha20: " + comment);

        // Verify user landmark is strictly preserved
        var userSym = program.getSymbolTable().getPrimarySymbol(userMarkerAddr);
        assertNotNull(userSym);
        assertEquals("user_crypto_checkpoint", userSym.getName());
        var userBm = program.getBookmarkManager().getBookmark(userMarkerAddr, BookmarkType.NOTE, "User Note");
        assertNotNull(userBm);
        assertEquals("User checkpoint", userBm.getComment());

        // Test idempotence
        boolean secondRun = analyzer.added(program, new AddressSet(startAddr, startAddr.add(memBytes.length - 1)),
                TaskMonitor.DUMMY, new MessageLog());
        assertTrue(secondRun);
        assertEquals("user_crypto_checkpoint", program.getSymbolTable().getPrimarySymbol(userMarkerAddr).getName());
    }
}
