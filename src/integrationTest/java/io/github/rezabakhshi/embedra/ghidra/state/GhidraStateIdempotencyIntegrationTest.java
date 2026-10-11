package io.github.rezabakhshi.embedra.ghidra.state;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityCategory;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityType;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.HeuristicFactor;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadCategory;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadConfidence;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLeadsReport;
import io.github.rezabakhshi.embedra.analyzers.logging.DiagnosticLogLevel;
import io.github.rezabakhshi.embedra.analyzers.logging.FormatStringDescriptor;
import io.github.rezabakhshi.embedra.analyzers.logging.LoggingCallSite;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.analyzers.strings.StringProvenance;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.analyzers.yara.CompiledYaraRuleset;
import io.github.rezabakhshi.embedra.analyzers.yara.YaraMatch;
import io.github.rezabakhshi.embedra.analyzers.yara.YaraRule;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.ghidra.crypto.GhidraCryptoApplicator;
import io.github.rezabakhshi.embedra.ghidra.ctf.GhidraCtfApplicator;
import io.github.rezabakhshi.embedra.ghidra.leads.GhidraSecurityLeadApplicator;
import io.github.rezabakhshi.embedra.ghidra.logging.GhidraLoggingApplicator;
import io.github.rezabakhshi.embedra.ghidra.stm32.Stm32SvdApplicator;
import io.github.rezabakhshi.embedra.ghidra.strings.GhidraStringApplicator;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.ghidra.yara.GhidraYaraApplicator;
import io.github.rezabakhshi.embedra.pack.Stm32SvdPack;
import io.github.rezabakhshi.embedra.pack.Stm32SvdPackLoader;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Proof suite verifying CORE-015 (Idempotency across enrichment reruns) and
 * CORE-016 (Preservation of user-created Ghidra state without silent overwrite).
 */
class GhidraStateIdempotencyIntegrationTest {

    private static final Object CONSUMER = new Object();

    private static final long FLASH_BASE = 0x08000000L;

    private static final int FLASH_SIZE = 0x10000;

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
        program = new ProgramDB("Idempotency and Preservation Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Initialize Flash Memory")) {
            Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(FLASH_BASE);
            byte[] initBytes = new byte[FLASH_SIZE];
            Arrays.fill(initBytes, (byte) 0x00);
            MemoryBlock block = program.getMemory().createInitializedBlock(
                    "FLASH", start, initBytes.length, (byte) 0, TaskMonitor.DUMMY, false);
            block.setRead(true);
            block.setExecute(true);
            tx.commit();
        }
    }

    @AfterEach
    void tearDown() {
        if (program != null) {
            program.release(CONSUMER);
        }
    }

    private Address addr(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    @Test
    void verifiesUserCreatedStatePreservationAndEnrichmentIdempotency() throws Exception {
        // ====================================================================
        // STEP 1: Inject user-created Ghidra state (symbols, comments, bookmarks,
        //         functions, custom data types, manual byte edits).
        // ====================================================================
        Address userSymbolAddr = addr(FLASH_BASE + 0x0100L);
        Address userCommentAddr = addr(FLASH_BASE + 0x0200L);
        Address userBookmarkAddr = addr(FLASH_BASE + 0x0300L);
        Address userFuncAddr = addr(FLASH_BASE + 0x0400L);
        Address userTypeAddr = addr(FLASH_BASE + 0x0500L);
        Address userByteEditAddr = addr(FLASH_BASE + 0x0600L);

        Structure customUserStruct = new StructureDataType("CustomUserStruct", 0);
        customUserStruct.add(ByteDataType.dataType, "field_magic", "User defined field");
        customUserStruct.add(ByteDataType.dataType, "field_status", "User status flag");

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Create User State")) {
            // 1. User label
            program.getSymbolTable().createLabel(userSymbolAddr, "user_security_checkpoint", SourceType.USER_DEFINED);

            // 2. User EOL & PRE comments
            program.getListing().setComment(userCommentAddr, CommentType.EOL, "USER_CRITICAL_EOL_COMMENT");
            program.getListing().setComment(userCommentAddr, CommentType.PRE, "USER_CRITICAL_PRE_COMMENT");

            // 3. User bookmark
            program.getBookmarkManager().setBookmark(
                    userBookmarkAddr, BookmarkType.NOTE, "User Note Category", "Custom Analyst Hypothesis");

            // 4. User function with custom signature/name
            Function userFunc = program.getFunctionManager().createFunction(
                    "user_crypto_decrypt_core",
                    userFuncAddr,
                    new AddressSet(userFuncAddr, userFuncAddr.add(32L)),
                    SourceType.USER_DEFINED);
            assertNotNull(userFunc);

            // 5. User data type
            DataUtilities.createData(program, userTypeAddr, customUserStruct, -1,
                    DataUtilities.ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);

            // 6. User manual byte edit
            program.getMemory().setBytes(userByteEditAddr,
                    new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF});

            tx.commit();
        }

        // Snapshot initial user state verification
        Symbol userSym = program.getSymbolTable().getPrimarySymbol(userSymbolAddr);
        assertNotNull(userSym);
        assertEquals("user_security_checkpoint", userSym.getName());
        assertEquals(SourceType.USER_DEFINED, userSym.getSource());

        assertEquals("USER_CRITICAL_EOL_COMMENT", program.getListing().getComment(CommentType.EOL, userCommentAddr));
        assertEquals("USER_CRITICAL_PRE_COMMENT", program.getListing().getComment(CommentType.PRE, userCommentAddr));

        Bookmark[] userBms = program.getBookmarkManager().getBookmarks(userBookmarkAddr);
        assertEquals(1, userBms.length);
        assertEquals("User Note Category", userBms[0].getCategory());
        assertEquals("Custom Analyst Hypothesis", userBms[0].getComment());

        Function fn = program.getFunctionManager().getFunctionAt(userFuncAddr);
        assertNotNull(fn);
        assertEquals("user_crypto_decrypt_core", fn.getName());

        Data userDataType = program.getListing().getDefinedDataAt(userTypeAddr);
        assertNotNull(userDataType);
        assertEquals("CustomUserStruct", userDataType.getDataType().getName());

        byte[] readBack = new byte[4];
        program.getMemory().getBytes(userByteEditAddr, readBack);
        assertEquals((byte) 0xDE, readBack[0]);
        assertEquals((byte) 0xAD, readBack[1]);
        assertEquals((byte) 0xBE, readBack[2]);
        assertEquals((byte) 0xEF, readBack[3]);

        // ====================================================================
        // STEP 2: Execute Enrichment Pass 1 across all applicators.
        // ====================================================================

        // A. Security Leads (one overlaps userCommentAddr to test non-destructive comment merge)
        SecurityLead lead1 = new SecurityLead(
                "LEAD-001", LeadCategory.PASSWORD_TOKEN_COMPARISON, LeadConfidence.HIGH, 0.95, LeadSeverity.CRITICAL,
                FLASH_BASE + 0x0200L, "strcmp", "admin_secret", "Admin credential check",
                List.of(HeuristicFactor.of("SECRET", "Hardcoded string", 0.5)), Map.of(), true);
        SecurityLead lead2 = new SecurityLead(
                "LEAD-002", LeadCategory.DEBUG_COMMAND, LeadConfidence.HIGH, 0.90, LeadSeverity.HIGH,
                FLASH_BASE + 0x0250L, null, "diag", "Diagnostic shell entry",
                List.of(HeuristicFactor.of("SHELL", "Shell entry", 0.5)), Map.of(), false);
        SecurityLeadsReport leadsReport = new SecurityLeadsReport(List.of(lead1, lead2));

        var leadReport1 = GhidraSecurityLeadApplicator.apply(program, leadsReport, TaskMonitor.DUMMY);
        assertEquals(2, leadReport1.totalLeads());
        assertEquals(2, leadReport1.bookmarksCreated());
        assertEquals(2, leadReport1.commentsCreated());

        // B. Crypto Applicator
        CryptoFinding crypto1 = new CryptoFinding(
                "CRYPTO-001", FLASH_BASE + 0x0350L, 32, CryptoCategory.CIPHER_SYMMETRIC,
                CryptoAlgorithm.AES_128, CryptoConfidence.CONFIRMED,
                Set.of(CryptoEvidenceLayer.CONSTANT_TABLE), "AES S-Box table",
                "0001020304050607", false, Map.of());
        var cryptoReport1 = GhidraCryptoApplicator.apply(program, List.of(crypto1), TaskMonitor.DUMMY);
        assertEquals(1, cryptoReport1.totalFindings());
        assertEquals(1, cryptoReport1.bookmarksCreated());
        assertEquals(1, cryptoReport1.commentsCreated());

        // C. Strings Applicator
        ExtractedString str1 = new ExtractedString(
                FLASH_BASE + 0x0450L, 20, StringEncoding.ASCII,
                "Embedded Bootloader", StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL, true);
        RecoveredStackString stackStr1 = new RecoveredStackString(
                FLASH_BASE + 0x0470L, 0x10L, "FLAG{test_token}", StringEncoding.ASCII,
                StringConfidence.CONFIRMED, FLASH_BASE + 0x0470L, FLASH_BASE + 0x0480L, 4);
        var stringReport1 = GhidraStringApplicator.apply(program, List.of(str1), List.of(stackStr1), TaskMonitor.DUMMY);
        assertEquals(2, stringReport1.totalStringsCount());
        assertEquals(2, stringReport1.bookmarksCreated());
        assertEquals(2, stringReport1.commentsCreated());

        // D. CTF Applicator
        CtfEntity ctf1 = new CtfEntity(
                "CTF-001", CtfEntityCategory.FLAG, CtfEntityType.FLAG, CtfSeverity.HIGH,
                StringConfidence.CONFIRMED, FLASH_BASE + 0x0550L, 16, "flag{state_test}", "CTF Flag", true);
        var ctfReport1 = GhidraCtfApplicator.apply(program, List.of(ctf1), TaskMonitor.DUMMY);
        assertEquals(1, ctfReport1.totalFindings());
        assertEquals(1, ctfReport1.bookmarksCreated());
        assertEquals(1, ctfReport1.commentsCreated());

        // E. Logging Applicator
        LoggingCallSite log1 = new LoggingCallSite(
                FLASH_BASE + 0x0650L, FLASH_BASE + 0x0660L, "printf", DiagnosticLogLevel.INFO,
                FormatStringDescriptor.empty(), Map.of(), "CONFIRMED", "Boot message");
        var logReport1 = GhidraLoggingApplicator.apply(program, List.of(log1), TaskMonitor.DUMMY);
        assertEquals(1, logReport1.totalCallSites());
        assertEquals(1, logReport1.bookmarksCreated());
        assertEquals(1, logReport1.commentsCreated());

        // F. YARA Applicator
        CompiledYaraRuleset ruleset = CompiledYaraRuleset.loadBuiltinRules(true, false);
        YaraRule chachaRule = ruleset.getRule("ChaCha20_Constant");
        assertNotNull(chachaRule, "ChaCha20_Constant rule must exist in builtin rules");
        YaraMatch yara1 = new YaraMatch(
                chachaRule, FLASH_BASE + 0x0750L, 0, 16, Map.of());
        var yaraReport1 = GhidraYaraApplicator.apply(program, List.of(yara1), TaskMonitor.DUMMY);
        assertEquals(1, yaraReport1.totalMatches());
        assertEquals(1, yaraReport1.bookmarksCreated());
        assertEquals(1, yaraReport1.commentsCreated());

        // ====================================================================
        // STEP 3: Verify User State is STRICTLY Preserved (CORE-016)
        // ====================================================================
        // 1. User label preserved
        Symbol preservedSym = program.getSymbolTable().getPrimarySymbol(userSymbolAddr);
        assertNotNull(preservedSym);
        assertEquals("user_security_checkpoint", preservedSym.getName());
        assertEquals(SourceType.USER_DEFINED, preservedSym.getSource());

        // 2. User comment at userCommentAddr was preserved, and lead comment was appended non-destructively
        String mergedComment = program.getListing().getComment(CommentType.EOL, userCommentAddr);
        assertNotNull(mergedComment);
        assertTrue(mergedComment.startsWith("USER_CRITICAL_EOL_COMMENT | "),
                "User comment must remain prefix of merged comment, was: " + mergedComment);
        assertTrue(mergedComment.contains("[Lead: Password / Token Comparison"),
                "Merged comment must contain appended lead annotation");
        assertEquals("USER_CRITICAL_PRE_COMMENT", program.getListing().getComment(CommentType.PRE, userCommentAddr));

        // 3. User bookmark preserved
        Bookmark[] bmsAtUserAddr = program.getBookmarkManager().getBookmarks(userBookmarkAddr);
        assertEquals(1, bmsAtUserAddr.length);
        assertEquals("User Note Category", bmsAtUserAddr[0].getCategory());
        assertEquals("Custom Analyst Hypothesis", bmsAtUserAddr[0].getComment());

        // 4. User function preserved
        Function preservedFunc = program.getFunctionManager().getFunctionAt(userFuncAddr);
        assertNotNull(preservedFunc);
        assertEquals("user_crypto_decrypt_core", preservedFunc.getName());
        assertEquals(SourceType.USER_DEFINED, preservedFunc.getSymbol().getSource());

        // 5. User data type preserved
        Data preservedData = program.getListing().getDefinedDataAt(userTypeAddr);
        assertNotNull(preservedData);
        assertEquals("CustomUserStruct", preservedData.getDataType().getName());

        // 6. User memory edit preserved
        byte[] userBytesRead = new byte[4];
        program.getMemory().getBytes(userByteEditAddr, userBytesRead);
        assertEquals((byte) 0xDE, userBytesRead[0]);
        assertEquals((byte) 0xAD, userBytesRead[1]);
        assertEquals((byte) 0xBE, userBytesRead[2]);
        assertEquals((byte) 0xEF, userBytesRead[3]);

        // Capture bookmark count after Pass 1
        int totalBookmarksPass1 = countAllBookmarks(program);
        assertEquals(9, totalBookmarksPass1, "1 user + 2 leads + 1 crypto + 2 strings + 1 ctf + 1 log + 1 yara");

        // ====================================================================
        // STEP 4: Execute Enrichment Pass 2 (Rerun with identical inputs - CORE-015)
        // ====================================================================
        var leadReport2 = GhidraSecurityLeadApplicator.apply(program, leadsReport, TaskMonitor.DUMMY);
        assertEquals(2, leadReport2.totalLeads());
        assertEquals(0, leadReport2.bookmarksCreated(), "Lead reapplication must not duplicate bookmarks");
        assertEquals(0, leadReport2.commentsCreated(), "Lead reapplication must not duplicate comments");

        var cryptoReport2 = GhidraCryptoApplicator.apply(program, List.of(crypto1), TaskMonitor.DUMMY);
        assertEquals(1, cryptoReport2.totalFindings());

        var stringReport2 = GhidraStringApplicator.apply(program, List.of(str1), List.of(stackStr1), TaskMonitor.DUMMY);
        assertEquals(2, stringReport2.totalStringsCount());

        var ctfReport2 = GhidraCtfApplicator.apply(program, List.of(ctf1), TaskMonitor.DUMMY);
        assertEquals(1, ctfReport2.totalFindings());

        var logReport2 = GhidraLoggingApplicator.apply(program, List.of(log1), TaskMonitor.DUMMY);
        assertEquals(1, logReport2.totalCallSites());

        var yaraReport2 = GhidraYaraApplicator.apply(program, List.of(yara1), TaskMonitor.DUMMY);
        assertEquals(1, yaraReport2.totalMatches());

        // ====================================================================
        // STEP 5: Verify Idempotency guarantees after Pass 2
        // ====================================================================
        int totalBookmarksPass2 = countAllBookmarks(program);
        assertEquals(totalBookmarksPass1, totalBookmarksPass2,
                "Total bookmarks count after rerun must be identical to Pass 1");

        // Verify comments are not duplicated
        String commentPass2 = program.getListing().getComment(CommentType.EOL, userCommentAddr);
        assertEquals(mergedComment, commentPass2, "Merged comment must not duplicate content on rerun");

        Address cryptoAddr = addr(FLASH_BASE + 0x0350L);
        String cryptoComment = program.getListing().getComment(CommentType.EOL, cryptoAddr);
        assertNotNull(cryptoComment);
        assertFalse(cryptoComment.contains("|"), "Single applicator comment should not have duplication pipe");

        // Verify user state remains intact after rerun
        assertEquals("user_security_checkpoint", program.getSymbolTable().getPrimarySymbol(userSymbolAddr).getName());
        assertEquals("user_crypto_decrypt_core", program.getFunctionManager().getFunctionAt(userFuncAddr).getName());
        assertEquals("CustomUserStruct", program.getListing().getDefinedDataAt(userTypeAddr).getDataType().getName());

        // ====================================================================
        // STEP 6: Execute Enrichment Pass 3 (Third rerun) to solidify proof
        // ====================================================================
        GhidraSecurityLeadApplicator.apply(program, leadsReport, TaskMonitor.DUMMY);
        GhidraCryptoApplicator.apply(program, List.of(crypto1), TaskMonitor.DUMMY);
        GhidraStringApplicator.apply(program, List.of(str1), List.of(stackStr1), TaskMonitor.DUMMY);
        GhidraCtfApplicator.apply(program, List.of(ctf1), TaskMonitor.DUMMY);
        GhidraLoggingApplicator.apply(program, List.of(log1), TaskMonitor.DUMMY);
        GhidraYaraApplicator.apply(program, List.of(yara1), TaskMonitor.DUMMY);

        int totalBookmarksPass3 = countAllBookmarks(program);
        assertEquals(totalBookmarksPass1, totalBookmarksPass3, "Bookmark count must remain stable on 3rd rerun");
        assertEquals(mergedComment, program.getListing().getComment(CommentType.EOL, userCommentAddr));
    }

    @Test
    void verifiesSvdApplicatorIdempotenceAndUserSymbolPreservation() throws Exception {
        // Load STM32 SVD Pack
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(
                Path.of("catalogs/stm32/2026-09-29/selection.json"),
                ParserLimits.defaults(), CancellationToken.none());
        Stm32SvdPack f103 = Stm32SvdPackLoader.load(
                Path.of("packs/stm32.stm32f103.svd/1.0.0"),
                ParserLimits.defaults(), CancellationToken.none());

        Address gpioaAddr = addr(0x40010800L);

        // Pre-create user label and user comment on peripheral register address
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Create User Peripheral State")) {
            program.getSymbolTable().createLabel(gpioaAddr, "my_custom_gpioa_label", SourceType.USER_DEFINED);
            program.getListing().setComment(gpioaAddr, CommentType.EOL, "USER_PERIPHERAL_CONFIG_NOTE");
            tx.commit();
        }

        // Apply SVD registers pass 1
        var report1 = Stm32SvdApplicator.applyRegisters(program, f103, "STM32F103C8T6", selection, TaskMonitor.DUMMY);
        assertTrue(report1.createdBlocks().size() > 0, "Must create SVD peripheral blocks");

        // Verify user label was preserved alongside imported label
        Symbol[] syms = program.getSymbolTable().getSymbols(gpioaAddr);
        boolean hasUserLabel = Arrays.stream(syms).anyMatch(s -> s.getName().equals("my_custom_gpioa_label")
                && s.getSource() == SourceType.USER_DEFINED);
        assertTrue(hasUserLabel, "User label on peripheral must be preserved");

        // Verify comment preserved
        String comment1 = program.getListing().getComment(CommentType.EOL, gpioaAddr);
        assertNotNull(comment1);
        assertTrue(comment1.contains("USER_PERIPHERAL_CONFIG_NOTE"));

        int totalBlocksPass1 = program.getMemory().getBlocks().length;
        int totalSymbolsPass1 = countAllSymbols(program);

        // Apply SVD registers pass 2 (Idempotency rerun)
        var report2 = Stm32SvdApplicator.applyRegisters(program, f103, "STM32F103C8T6", selection, TaskMonitor.DUMMY);
        assertEquals(0, report2.createdBlocks().size(), "Second SVD run must create 0 new blocks");
        assertEquals(0, report2.createdSymbols().size(), "Second SVD run must create 0 new symbols");
        assertEquals(0, report2.createdDataAddresses().size(), "Second SVD run must create 0 new data types");
        assertEquals(0, report2.createdComments(), "Second SVD run must create 0 new comments");

        assertEquals(totalBlocksPass1, program.getMemory().getBlocks().length, "Block count must remain unchanged");
        assertEquals(totalSymbolsPass1, countAllSymbols(program), "Symbol count must remain unchanged");

        // Verify comment not duplicated
        String comment2 = program.getListing().getComment(CommentType.EOL, gpioaAddr);
        assertEquals(comment1, comment2, "Peripheral comment must not duplicate on rerun");
    }

    private static int countAllBookmarks(Program program) {
        int count = 0;
        var iter = program.getBookmarkManager().getBookmarksIterator();
        while (iter.hasNext()) {
            iter.next();
            count++;
        }
        return count;
    }

    private static int countAllSymbols(Program program) {
        int count = 0;
        var iter = program.getSymbolTable().getAllSymbols(true);
        while (iter.hasNext()) {
            iter.next();
            count++;
        }
        return count;
    }
}
