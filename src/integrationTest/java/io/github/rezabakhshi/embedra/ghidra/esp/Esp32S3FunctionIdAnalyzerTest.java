package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.github.rezabakhshi.embedra.analyzers.esp.Esp32S3FunctionIdStatus;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class Esp32S3FunctionIdAnalyzerTest {
    private static final String ESP32S3_LANGUAGE_ID = "Xtensa:LE:32:esp32s3";

    private static final String GENERIC_XTENSA_LANGUAGE_ID = "Xtensa:LE:32:default";

    private static final long ALPHA_ADDRESS = 0x42000020L;

    private static final long BETA_ADDRESS = 0x4200005eL;

    private static final int FUNCTION_SIZE = 62;

    private static final String LIBRARY_FAMILY = "ESP-IDF test library";

    private static final String LIBRARY_VERSION = "v0-test";

    private static final String LIBRARY_VARIANT = "mechanics";

    private static final String DESCRIPTOR_IDF_VERSION = "test-idf-version";

    private static final List<File> attachedDatabases = new ArrayList<>();

    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            String installDirectory = System.getenv("GHIDRA_INSTALL_DIR");
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDirectory)), configuration);
        }
    }

    @AfterEach
    void detachTestDatabases() {
        FidFileManager manager = FidFileManager.getInstance();
        for (File file : attachedDatabases) {
            manager.getFidFiles().stream()
                .filter(candidate -> candidate.getPath().equals(file.getAbsolutePath()))
                .forEach(manager::removeUserFile);
        }
        attachedDatabases.clear();
    }

    @Test
    void analyzerIsExplicitOptInAndScopedToEsp32S3Variant() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Object consumer = new Object();
        ProgramDB program = mechanicsProgram("fid-optin-scope", false, consumer);
        try {
            assertTrue(analyzer.canAnalyze(program));
            assertFalse(analyzer.getDefaultEnablement(program));
        } finally {
            program.release(consumer);
        }
        Program generic = (Program) java.lang.reflect.Proxy.newProxyInstance(
            Program.class.getClassLoader(), new Class<?>[] {Program.class},
            (proxy, method, arguments) -> {
                if ("getLanguageID".equals(method.getName())) {
                    return new LanguageID(GENERIC_XTENSA_LANGUAGE_ID);
                }
                return switch (method.getReturnType().getSimpleName()) {
                    case "boolean" -> false;
                    case "int" -> 0;
                    case "long" -> 0L;
                    default -> null;
                };
            });
        assertFalse(analyzer.canAnalyze(generic));
    }

    @Test
    void absentDatabaseReportsStableCodeWithoutMutation() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Object consumer = new Object();
        ProgramDB program = mechanicsProgram("fid-absent", false, consumer);
        try {
            Map<String, List<String>> before = symbolState(program);
            MessageLog log = new MessageLog();
            assertTrue(runAnalyzer(analyzer, program, null, null, log, TaskMonitor.DUMMY));
            assertEquals(Esp32S3FunctionIdStatus.DATABASE_ABSENT.code(), statusOption(program));
            assertTrue(log.toString()
                .contains(Esp32S3FunctionIdStatus.DATABASE_ABSENT.code()));

            Path missing = Path.of(System.getProperty("java.io.tmpdir"),
                "embedra-definitely-missing-" + System.nanoTime() + ".fidb");
            assertTrue(runAnalyzer(analyzer, program, missing, missing, new MessageLog(),
                TaskMonitor.DUMMY));
            assertEquals(Esp32S3FunctionIdStatus.DATABASE_ABSENT.code(), statusOption(program));
            assertEquals(before, symbolState(program));
        } finally {
            program.release(consumer);
        }
    }

    @Test
    void strippedSameBuildFunctionsReceiveOptInFidNamesAndProvenance() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            MessageLog log = new MessageLog();
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, log,
                TaskMonitor.DUMMY), log::toString);

            assertEquals("embedra_fid_alpha", functionName(stripped, ALPHA_ADDRESS));
            assertEquals("embedra_fid_beta", functionName(stripped, BETA_ADDRESS));
            assertTrue(functionAt(stripped, ALPHA_ADDRESS).getComment()
                .contains(LIBRARY_FAMILY));
            assertNotNull(stripped.getBookmarkManager().getBookmark(
                address(stripped, ALPHA_ADDRESS), BookmarkType.ANALYSIS,
                "Function ID Analyzer"));
            assertEquals(Esp32S3FunctionIdStatus.MATCHES_APPLIED.code(),
                statusOption(stripped));
            Options options = stripped.getOptions(EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE);
            assertEquals(2, options.getInt(
                EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_EXAMINED_KEY, -1));
            assertEquals(2, options.getInt(
                EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_RENAMED_KEY, -1));
            assertEquals(0, options.getInt(
                EmbedraEsp32S3FunctionIdAnalyzer.AMBIGUOUS_FUNCTIONS_KEY, -1));
            assertEquals("UNCERTAIN", options.getString(
                EmbedraEsp32S3FunctionIdAnalyzer.VERSION_EVIDENCE_KEY, ""));
            assertEquals(sha256(database), options.getString(
                EmbedraEsp32S3FunctionIdAnalyzer.DATABASE_SHA256_KEY, ""));
            assertEquals(LIBRARY_FAMILY + "|" + LIBRARY_VERSION + "|" + LIBRARY_VARIANT,
                options.getString(EmbedraEsp32S3FunctionIdAnalyzer.LIBRARY_IDENTITY_KEY, ""));
            assertEquals(ESP32S3_LANGUAGE_ID, options.getString(
                EmbedraEsp32S3FunctionIdAnalyzer.TARGET_LANGUAGE_KEY, ""));
            assertTrue(log.toString()
                .contains(Esp32S3FunctionIdStatus.MATCHES_APPLIED.code()));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    @Test
    void userDefinedNamesAndCommentsArePreserved() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-user-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-user-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-user-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(stripped,
                    "User renames beta")) {
                Function beta = functionAt(stripped, BETA_ADDRESS);
                beta.setName("keep_this_user_name", SourceType.USER_DEFINED);
                beta.setComment("user analysis note");
                transaction.commit();
            }
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, new MessageLog(),
                TaskMonitor.DUMMY));

            assertEquals("keep_this_user_name", functionName(stripped, BETA_ADDRESS));
            assertEquals("user analysis note", functionAt(stripped, BETA_ADDRESS).getComment());
            assertEquals("embedra_fid_alpha", functionName(stripped, ALPHA_ADDRESS));
            assertEquals(Esp32S3FunctionIdStatus.MATCHES_APPLIED.code(), statusOption(stripped));
            assertEquals(1, stripped.getOptions(EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE)
                .getInt(EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_RENAMED_KEY, -1));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    @Test
    void databaseDigestMismatchRefusesWithoutMutation() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-digest-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-digest-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-digest-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            Files.writeString(descriptor, Files.readString(descriptor)
                .replace(sha256(database),
                    "0000000000000000000000000000000000000000000000000000000000000000"));
            Map<String, List<String>> before = symbolState(stripped);
            MessageLog log = new MessageLog();
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, log,
                TaskMonitor.DUMMY), log::toString);
            assertEquals(Esp32S3FunctionIdStatus.DATABASE_DIGEST_MISMATCH.code(),
                statusOption(stripped));
            assertEquals(before, symbolState(stripped));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    @Test
    void conflictingAttachedDatabaseRefusesAndPreservesBothAttachments() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-configured-", ".fidb");
        Path otherDatabase = Files.createTempFile("embedra-fid-other-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-conflict-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-conflict-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            buildDatabase(otherDatabase.toFile(), source, GENERIC_XTENSA_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            Map<String, List<String>> before = symbolState(stripped);
            MessageLog log = new MessageLog();
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, log,
                TaskMonitor.DUMMY), log::toString);
            assertEquals(Esp32S3FunctionIdStatus.DATABASE_CONFLICT.code(),
                statusOption(stripped));
            assertEquals(before, symbolState(stripped));
            assertNotNull(findRegisteredFile(database.toFile()));
            assertNotNull(findRegisteredFile(otherDatabase.toFile()));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
            Files.deleteIfExists(otherDatabase);
        }
    }

    @Test
    void genericVariantLibraryRefusedDespiteGhidraFamilyApplicability() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-variant-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-variant-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-variant-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, GENERIC_XTENSA_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            Map<String, List<String>> before = symbolState(stripped);
            MessageLog log = new MessageLog();
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, log,
                TaskMonitor.DUMMY), log::toString);
            assertEquals(Esp32S3FunctionIdStatus.TARGET_INCOMPATIBLE.code(),
                statusOption(stripped));
            assertEquals(before, symbolState(stripped));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
        }

        // Ghidra 12.1.3 family-level applicability accepts the other Xtensa variant;
        // applicability is not match-validity evidence (recorded by ADR 0021).
        attachDatabase(database.toFile());
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(ESP32S3_LANGUAGE_ID));
        assertTrue(new FidService().canProcess(language));
        Files.deleteIfExists(database);
    }

    @Test
    void versionEvidenceMismatchRefusesAndMatchConfirms() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-version-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-version-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-version-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            setAppDescriptionVersion(stripped, "definitely-other-version");
            Map<String, List<String>> before = symbolState(stripped);
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, new MessageLog(),
                TaskMonitor.DUMMY));
            assertEquals(Esp32S3FunctionIdStatus.VERSION_INCOMPATIBLE.code(),
                statusOption(stripped));
            assertEquals(before, symbolState(stripped));

            setAppDescriptionVersion(stripped, DESCRIPTOR_IDF_VERSION);
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, new MessageLog(),
                TaskMonitor.DUMMY));
            assertEquals(Esp32S3FunctionIdStatus.MATCHES_APPLIED.code(), statusOption(stripped));
            assertEquals("CONFIRMED", stripped.getOptions(
                EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE).getString(
                    EmbedraEsp32S3FunctionIdAnalyzer.VERSION_EVIDENCE_KEY, ""));
            assertEquals("embedra_fid_alpha", functionName(stripped, ALPHA_ADDRESS));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    @Test
    void invalidProvenanceDescriptorReportsStableCodeWithoutMutation() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-invalid-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-invalid-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-invalid-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            Files.writeString(descriptor, Files.readString(descriptor)
                .replace("\"chipId\": 9,", "\"chipId\": 0,"));
            Map<String, List<String>> before = symbolState(stripped);
            MessageLog log = new MessageLog();
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, log,
                TaskMonitor.DUMMY), log::toString);
            assertEquals(Esp32S3FunctionIdStatus.PROVENANCE_INVALID.code(),
                statusOption(stripped));
            assertEquals(before, symbolState(stripped));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    @Test
    void ambiguousCandidatesAreReportedAndNeverArbitrarilyRenamed() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-ambig-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-ambig-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-ambig-stripped", false, strippedConsumer);
        try {
            buildAmbiguousDatabase(database.toFile(), source);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            MessageLog log = new MessageLog();
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, log,
                TaskMonitor.DUMMY), log::toString);
            assertEquals(Esp32S3FunctionIdStatus.AMBIGUOUS_MATCHES.code(),
                statusOption(stripped));
            assertEquals(1, stripped.getOptions(EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE)
                .getInt(EmbedraEsp32S3FunctionIdAnalyzer.AMBIGUOUS_FUNCTIONS_KEY, -1));
            Function alpha = functionAt(stripped, ALPHA_ADDRESS);
            assertTrue(alpha.getName().startsWith("FID_conflict:"),
                "ambiguous candidates must be marked as a conflict, not assigned one name");
            assertTrue(alpha.getComment().contains("Multiple Matches"));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    @Test
    void repeatedRunIsIdempotentAndSnapshotStable() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-idem-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-idem-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-idem-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, new MessageLog(),
                TaskMonitor.DUMMY));
            Map<String, List<String>> afterFirst = symbolState(stripped);
            assertTrue(runAnalyzer(analyzer, stripped, database, descriptor, new MessageLog(),
                TaskMonitor.DUMMY));
            assertEquals(afterFirst, symbolState(stripped));
            Options options = stripped.getOptions(EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE);
            assertEquals(Esp32S3FunctionIdStatus.ALREADY_APPLIED.code(), statusOption(stripped));
            assertEquals(2, options.getInt(
                EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_EXAMINED_KEY, -1));
            assertEquals(0, options.getInt(
                EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_RENAMED_KEY, -1));
            assertEquals(0, options.getInt(
                EmbedraEsp32S3FunctionIdAnalyzer.AMBIGUOUS_FUNCTIONS_KEY, -1));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    @Test
    void cancellationRollsBackEveryRename() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-cancel-", ".fidb");
        Object sourceConsumer = new Object();
        Object strippedConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-cancel-source", true, sourceConsumer);
        ProgramDB stripped = mechanicsProgram("fid-cancel-stripped", false, strippedConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
            cancelled.cancel();
            assertThrows(CancelledException.class, () -> runAnalyzer(analyzer, stripped,
                database, descriptor, new MessageLog(), cancelled));
            assertEquals(Esp32S3FunctionIdStatus.CANCELLED.code(), statusOption(stripped));
            assertEquals("FUN_42000020", functionName(stripped, ALPHA_ADDRESS));
            assertEquals("FUN_4200005e", functionName(stripped, BETA_ADDRESS));
        } finally {
            stripped.release(strippedConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    @Test
    void independentRunsShareDeterministicOutcomes() throws Exception {
        EmbedraEsp32S3FunctionIdAnalyzer analyzer = new EmbedraEsp32S3FunctionIdAnalyzer();
        Path database = Files.createTempFile("embedra-fid-det-", ".fidb");
        Object sourceConsumer = new Object();
        Object firstConsumer = new Object();
        Object secondConsumer = new Object();
        ProgramDB source = mechanicsProgram("fid-det-source", true, sourceConsumer);
        ProgramDB first = mechanicsProgram("fid-det-a", false, firstConsumer);
        ProgramDB second = mechanicsProgram("fid-det-b", false, secondConsumer);
        try {
            buildDatabase(database.toFile(), source, ESP32S3_LANGUAGE_ID);
            Path descriptor = writeDescriptor(database, DESCRIPTOR_IDF_VERSION,
                ESP32S3_LANGUAGE_ID);
            assertTrue(runAnalyzer(analyzer, first, database, descriptor, new MessageLog(),
                TaskMonitor.DUMMY));
            assertTrue(runAnalyzer(analyzer, second, database, descriptor, new MessageLog(),
                TaskMonitor.DUMMY));
            assertEquals(symbolState(first), symbolState(second));
            assertEquals(outcomeState(first), outcomeState(second));
        } finally {
            second.release(secondConsumer);
            first.release(firstConsumer);
            source.release(sourceConsumer);
            Files.deleteIfExists(database);
        }
    }

    private static boolean runAnalyzer(EmbedraEsp32S3FunctionIdAnalyzer analyzer, Program program,
            Path database, Path descriptor, MessageLog log, TaskMonitor monitor)
            throws ghidra.util.exception.CancelledException {
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(program,
                "Configure Embedra Function ID options")) {
            Options programOptions = program.getOptions(
                EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE);
            programOptions.setString(EmbedraEsp32S3FunctionIdAnalyzer.DATABASE_PATH_OPTION,
                database == null ? "" : database.toString());
            programOptions.setString(EmbedraEsp32S3FunctionIdAnalyzer.DESCRIPTOR_PATH_OPTION,
                descriptor == null ? "" : descriptor.toString());
            transaction.commit();
        }
        AddressSetView set = program.getMemory().getExecuteSet();
        boolean result = analyzer.added(program, set, monitor, log);
        if (!result || log.toString().contains(
                Esp32S3FunctionIdStatus.DATABASE_CONFLICT.code())) {
            System.out.println("EMBEDRA-FID DEBUG:\n" + log);
        }
        return result;
    }

    private static ProgramDB mechanicsProgram(String name, boolean trustedNames, Object consumer)
            throws Exception {
        byte[] code = fixture("/fixtures/esp32s3/fid-mechanics/embedra-fid-mechanics.bin");
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(ESP32S3_LANGUAGE_ID));
        ProgramDB program = new ProgramDB(name, language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), consumer);
        boolean handedOff = false;
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(program,
                "Map mechanics code")) {
            Address start = language.getDefaultSpace().getAddress(ALPHA_ADDRESS);
            var block = program.getMemory().createInitializedBlock("fid-mechanics-text", start,
                new ByteArrayInputStream(code), code.length, TaskMonitor.DUMMY, false);
            block.setExecute(true);
            block.setRead(true);
            var disassembler = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null);
            long first = disassembler.disassemble(start,
                new AddressSet(start, start.add(FUNCTION_SIZE - 1))).getNumAddresses();
            Address beta = language.getDefaultSpace().getAddress(BETA_ADDRESS);
            long second = disassembler.disassemble(beta,
                new AddressSet(beta, beta.add(FUNCTION_SIZE - 1))).getNumAddresses();
            long decoded = first + second;
            if (decoded != code.length) {
                throw new IllegalStateException("Mechanics fixture did not fully disassemble ("
                    + decoded + " of " + code.length + ")");
            }
            createFunction(program, ALPHA_ADDRESS, trustedNames);
            createFunction(program, BETA_ADDRESS, trustedNames);
            transaction.commit();
            handedOff = true;
            return program;
        } finally {
            if (!handedOff) {
                program.release(consumer);
            }
        }
    }

    private static void createFunction(Program program, long offset, boolean trustedNames)
            throws Exception {
        Address entry = address(program, offset);
        Address end = address(program, offset + FUNCTION_SIZE - 1);
        String name;
        SourceType source;
        if (trustedNames) {
            name = offset == ALPHA_ADDRESS ? "embedra_fid_alpha" : "embedra_fid_beta";
            source = SourceType.USER_DEFINED;
        } else {
            name = offset == ALPHA_ADDRESS ? "FUN_42000020" : "FUN_4200005e";
            source = SourceType.DEFAULT;
        }
        program.getFunctionManager().createFunction(name, entry, new AddressSet(entry, end),
            source);
    }

    private static void buildDatabase(File database, Program source, String libraryLanguageId)
            throws Exception {
        Files.deleteIfExists(database.toPath());
        FidFileManager manager = FidFileManager.getInstance();
        manager.createNewFidDatabase(database);
        attachedDatabases.add(database);
        FidFile fidFile = findRegisteredFile(database);
        FidDB db = fidFile.getFidDB(true);
        try {
            LibraryRecord library = db.createNewLibrary(LIBRARY_FAMILY, LIBRARY_VERSION,
                LIBRARY_VARIANT, Application.getApplicationVersion(),
                new LanguageID(libraryLanguageId), 1, 0, new CompilerSpecID("default"));
            assertNotNull(library);
            FidService service = new FidService();
            for (Function function : source.getFunctionManager().getFunctions(true)) {
                db.createNewFunction(library, service.hashFunction(function),
                    function.getName(), function.getEntryPoint().getOffset(),
                    "/embedra-test/" + source.getName(), true);
            }
            db.saveDatabase("Embedra Function ID test ingest", TaskMonitor.DUMMY);
        } finally {
            db.close();
        }
    }

    private static void buildAmbiguousDatabase(File database, Program source) throws Exception {
        Files.deleteIfExists(database.toPath());
        FidFileManager manager = FidFileManager.getInstance();
        manager.createNewFidDatabase(database);
        attachedDatabases.add(database);
        FidFile fidFile = findRegisteredFile(database);
        FidDB db = fidFile.getFidDB(true);
        try {
            LibraryRecord library = db.createNewLibrary(LIBRARY_FAMILY, LIBRARY_VERSION,
                LIBRARY_VARIANT, Application.getApplicationVersion(),
                new LanguageID(ESP32S3_LANGUAGE_ID), 1, 0, new CompilerSpecID("default"));
            FidService service = new FidService();
            Function alpha = source.getFunctionManager().getFunctionAt(
                address(source, ALPHA_ADDRESS));
            db.createNewFunction(library, service.hashFunction(alpha), "embedra_fid_alpha",
                alpha.getEntryPoint().getOffset(), "/embedra-test/" + source.getName(), true);
            db.createNewFunction(library, service.hashFunction(alpha), "unrelated_impostor",
                alpha.getEntryPoint().getOffset(), "/embedra-test/" + source.getName(), true);
            Function beta = source.getFunctionManager().getFunctionAt(
                address(source, BETA_ADDRESS));
            db.createNewFunction(library, service.hashFunction(beta), "embedra_fid_beta",
                beta.getEntryPoint().getOffset(), "/embedra-test/" + source.getName(), true);
            db.saveDatabase("Embedra Function ID test ingest", TaskMonitor.DUMMY);
        } finally {
            db.close();
        }
    }

    private static FidFile findRegisteredFile(File database) {
        return FidFileManager.getInstance().getFidFiles().stream()
            .filter(candidate -> candidate.getPath().equals(database.getAbsolutePath()))
            .findFirst().orElseThrow();
    }

    private static void attachDatabase(File database) {
        FidFileManager manager = FidFileManager.getInstance();
        manager.getFidFiles().stream()
            .filter(candidate -> candidate.getPath().equals(database.getAbsolutePath()))
            .toList().forEach(manager::removeUserFile);
        assertNotNull(manager.addUserFidFile(database));
        attachedDatabases.add(database);
    }

    private static Path writeDescriptor(Path database, String idfVersion, String languageId)
            throws IOException {
        String json = """
            {
              "schemaId": "urn:embedra:schema:esp32s3-fidb-provenance:1",
              "artifactId": "esp32s3-fid-mechanics",
              "targetId": "esp32s3",
              "chipId": 9,
              "languageId": "%s",
              "compilerSpecId": "default",
              "idfVersion": "%s",
              "idfRevision": "662a3be354759d9487bf4b1a629fadb766cb1800",
              "toolchain": "xtensa-esp-elf esp-15.2.0_20251204 (gcc 15.2.0)",
              "optimization": "Os",
              "sdkconfigSha256": "%s",
              "referenceElfSha256": "%s",
              "strippedImageSha256": "%s",
              "fidbSha256": "%s",
              "functionCount": 2,
              "generatorCommand": "./scripts/generate-esp32s3-fid-ref.sh build",
              "ghidraVersion": "12.1.3",
              "libraryFamily": "%s",
              "libraryVersion": "%s",
              "libraryVariant": "%s",
              "components": [
                {"name": "embedra-test/main", "license": "Apache-2.0", "redistribution": "ALLOWED"}
              ],
              "redistribution": "ALLOWED"
            }
            """.formatted(languageId, idfVersion, sha("sdkconfig"), sha("reference-elf"),
                sha("stripped-image"), sha256(database), LIBRARY_FAMILY, LIBRARY_VERSION,
                LIBRARY_VARIANT);
        Path descriptor = Files.createTempFile("embedra-fid-descriptor-", ".json");
        Files.writeString(descriptor, json);
        return descriptor;
    }

    private static String sha(String seed) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(seed.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String sha256(Path path) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(Files.readAllBytes(path)));
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static void setAppDescriptionVersion(Program program, String version) {
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(program,
                "Record ESP-IDF version evidence")) {
            program.getOptions(EmbedraEsp32S3FunctionIdAnalyzer.APP_DESCRIPTION_OPTIONS)
                .setString(EmbedraEsp32S3FunctionIdAnalyzer.APP_DESCRIPTION_IDF_VERSION_KEY,
                    version);
            transaction.commit();
        }
    }

    private static String statusOption(Program program) {
        return program.getOptions(EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE)
            .getString(EmbedraEsp32S3FunctionIdAnalyzer.STATUS_CODE_KEY, "");
    }

    private static Map<String, String> outcomeState(Program program) {
        Options options = program.getOptions(EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE);
        Map<String, String> state = new TreeMap<>();
        state.put("status", statusOption(program));
        state.put("examined", String.valueOf(options.getInt(
            EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_EXAMINED_KEY, -1)));
        state.put("renamed", String.valueOf(options.getInt(
            EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_RENAMED_KEY, -1)));
        state.put("ambiguous", String.valueOf(options.getInt(
            EmbedraEsp32S3FunctionIdAnalyzer.AMBIGUOUS_FUNCTIONS_KEY, -1)));
        state.put("evidence", options.getString(
            EmbedraEsp32S3FunctionIdAnalyzer.VERSION_EVIDENCE_KEY, ""));
        state.put("database", options.getString(
            EmbedraEsp32S3FunctionIdAnalyzer.DATABASE_SHA256_KEY, ""));
        state.put("library", options.getString(
            EmbedraEsp32S3FunctionIdAnalyzer.LIBRARY_IDENTITY_KEY, ""));
        state.put("language", options.getString(
            EmbedraEsp32S3FunctionIdAnalyzer.TARGET_LANGUAGE_KEY, ""));
        return state;
    }

    private static String functionName(Program program, long offset) {
        Function function = functionAt(program, offset);
        return function == null ? null : function.getName();
    }

    private static Function functionAt(Program program, long offset) {
        return program.getFunctionManager().getFunctionAt(address(program, offset));
    }

    private static Address address(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static Map<String, List<String>> symbolState(Program program) {
        Map<String, List<String>> state = new LinkedHashMap<>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            List<String> names = new ArrayList<>();
            for (Symbol symbol : program.getSymbolTable().getSymbols(function.getEntryPoint())) {
                names.add(symbol.getName() + "/" + symbol.getSource());
            }
            Collections.sort(names);
            state.put(function.getEntryPoint() + "#names", names);
            state.put(function.getEntryPoint() + "#comment",
                List.of(String.valueOf(function.getComment())));
        }
        List<String> bookmarks = new ArrayList<>();
        var iterator = program.getBookmarkManager().getBookmarksIterator(
            BookmarkType.ANALYSIS);
        while (iterator.hasNext()) {
            Bookmark bookmark = iterator.next();
            bookmarks.add(bookmark.getAddress() + ":" + bookmark.getCategory() + ":"
                + bookmark.getComment());
        }
        Collections.sort(bookmarks);
        state.put("#bookmarks", bookmarks);
        return state;
    }

    private static byte[] fixture(String resource) throws IOException {
        try (InputStream input = Esp32S3FunctionIdAnalyzerTest.class
                .getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("Missing fixture " + resource);
            }
            return input.readAllBytes();
        }
    }
}
