package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.esp.Esp32S3FidProvenance;
import io.github.rezabakhshi.embedra.analyzers.esp.Esp32S3FunctionIdStatus;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.formats.esp.EspImageSegment;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.pack.RedistributionStatus;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Digest- and artifact-gated ESP32-S3 Function ID pilot measurements against the
 * committed reference build, database, provenance descriptor, and license audit.
 */
class Esp32S3FunctionIdPilotFixturesTest {
    private record RetainedProgram(Program program, Object consumer) {
    }

    private static final List<RetainedProgram> LOADED_PROGRAMS = new ArrayList<>();

    private static final Path PROJECT =
        Path.of(System.getProperty("embedra.projectDir"));

    private static final String DATABASE_FILE =
        "esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb";

    private static final String DESCRIPTOR_FILE =
        "esp-idf-v6.0-662a3be35475-esp32s3-Os.json";

    private static final String RESTRICTED_DUMP_SHA256 =
        "837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de";

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
    void closeLoadedPrograms() {
        LOADED_PROGRAMS.forEach(loaded -> loaded.program().release(loaded.consumer()));
        LOADED_PROGRAMS.clear();
    }

    @Test
    void shippedDescriptorMatchesEveryShippedArtifact() throws Exception {
        Esp32S3FidProvenance provenance = parseDescriptor();
        assertEquals("v6.0", provenance.idfVersion());
        assertEquals("662a3be354759d9487bf4b1a629fadb766cb1800",
            provenance.idfRevision());
        assertEquals("Xtensa:LE:32:esp32s3", provenance.languageId());
        assertEquals("ESP-IDF", provenance.libraryFamily());
        assertEquals(RedistributionStatus.ALLOWED, provenance.redistribution());
        assertTrue(provenance.components().size() >= 10);
        assertEquals(sha256(fidPath(DATABASE_FILE)), provenance.fidbSha256());
        assertEquals(sha256(image("embedra-fid-ref-app-a.bin")),
            provenance.strippedImageSha256());
        assertEquals(sha256(PROJECT.resolve(
            "src/test/resources/fixtures/esp32s3/fid/embedra-fid-ref-app-a.elf")),
            provenance.referenceElfSha256());
        String audit = Files.readString(PROJECT.resolve(
            "fid/esp32s3/esp-idf-v6.0-662a3be35475-esp32s3-Os.audit.json"));
        assertTrue(audit.contains("\"redistribution\": \"ALLOWED\""));
        assertTrue(audit.contains("EXCLUDED_FROM_FIDB"));
    }

    @Test
    void strippedSameBuildImageReceivesVerifiedIdfNames() throws Exception {
        Object consumer = new Object();
        ProgramDB program = loadStrippedImage("embedra-fid-ref-app-a.bin", consumer);
        Map<Long, Set<String>> oracle;
        oracle = createOracleFunctions(program,
            "esp32s3-fid-reference-appa.symbols.json");
            PilotRun run = runPilot(program);
            assertEquals(Esp32S3FunctionIdStatus.AMBIGUOUS_MATCHES.code(),
                run.status());
            assertEquals("CONFIRMED", run.evidence());
            assertEquals(720, run.examined());
            assertEquals(705, run.renamed());
            assertEquals(26, run.ambiguous());
            assertNoFalseRenames(program, oracle);
            assertEquals("app_main", namedOracleFunction(program, oracle, "app_main"));
        assertEquals("esp_log_timestamp",
            namedOracleFunction(program, oracle, "esp_log_timestamp"));
    }

    @Test
    void crossApplicationImageReceivesSharedIdfNames() throws Exception {
        Object consumer = new Object();
        ProgramDB program = loadStrippedImage("embedra-fid-cross-app-b.bin", consumer);
        Map<Long, Set<String>> oracle = createOracleFunctions(program,
            "esp32s3-fid-reference-appb.symbols.json");
            PilotRun run = runPilot(program);
            assertEquals(Esp32S3FunctionIdStatus.AMBIGUOUS_MATCHES.code(),
                run.status());
            assertEquals(717, run.examined());
            assertEquals(702, run.renamed());
            assertEquals(26, run.ambiguous());
            assertNoFalseRenames(program, oracle);
            assertEquals("esp_log_timestamp",
                namedOracleFunction(program, oracle, "esp_log_timestamp"));
            String ownMain = namedOracleFunction(program, oracle, "app_main");
            assertTrue(ownMain.startsWith("FUN_"),
                "app-b's different app_main body must not be named from the"
                    + " app-a database: " + ownMain);
            String ownHelper = namedOracleFunction(program, oracle,
                "embedra_fid_variant");
        assertTrue(ownHelper.startsWith("FUN_"),
            "app-b-only code is not in the app-a database: " + ownHelper);
    }

    @Test
    void changedOptimizationProducesFewerMatchesAndNeverAWrongName()
            throws Exception {
        Object sameConsumer = new Object();
        Object otherConsumer = new Object();
        ProgramDB sameBuild = loadStrippedImage("embedra-fid-ref-app-a.bin",
            sameConsumer);
        Map<Long, Set<String>> sameOracle = createOracleFunctions(sameBuild,
            "esp32s3-fid-reference-appa.symbols.json");
        int sameRenamed = runPilot(sameBuild).renamed();
        assertEquals(705, sameRenamed);
        assertNoFalseRenames(sameBuild, sameOracle);
        releaseLoadedProgram(sameBuild);

        ProgramDB optimized = loadStrippedImage("embedra-fid-ref-app-a-o2.bin",
            otherConsumer);
        Map<Long, Set<String>> optimizedOracle = createOracleFunctions(optimized,
            "esp32s3-fid-reference-appa-o2.symbols.json");
        PilotRun optimizedRun = runPilot(optimized);
        assertEquals(Esp32S3FunctionIdStatus.AMBIGUOUS_MATCHES.code(),
            optimizedRun.status());
        assertEquals(71, optimizedRun.examined());
        assertEquals(66, optimizedRun.renamed());
        assertEquals(7, optimizedRun.ambiguous());
        assertNoFalseRenames(optimized, optimizedOracle);
        assertTrue(optimizedRun.renamed() < sameRenamed,
            "-O2 build must match strictly fewer functions than the same -Os"
                + " build (" + optimizedRun.renamed() + " vs " + sameRenamed + ")");
    }

    @Test
    void unrelatedCodeNeverReceivesAutomaticIdfNames() throws Exception {
        byte[] image = freestandingImage();
        EspImage parsed = EspImageParser.parseForChip(image, 9,
            ParserLimits.defaults(), CancellationToken.none());
        EspImageSegment code = parsed.segments().stream()
            .filter(segment -> segment.loadAddress() == 0x40378000L)
            .findFirst().orElseThrow();
        byte[] text = Arrays.copyOfRange(image,
            Math.toIntExact(code.dataSourceRange().offset()),
            Math.toIntExact(code.dataSourceRange().offset()
                + code.dataSourceRange().length()));
        Object consumer = new Object();
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("Xtensa:LE:32:esp32s3"));
        ProgramDB program = new ProgramDB("fid-unrelated", language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), consumer);
        try {
            try (GhidraProgramTransaction transaction =
                    GhidraProgramTransaction.start(program, "Map unrelated code")) {
                Address start = language.getDefaultSpace().getAddress(0x40378000L);
                var block = program.getMemory().createInitializedBlock("text", start,
                    new ByteArrayInputStream(text), text.length, TaskMonitor.DUMMY,
                    false);
                block.setExecute(true);
                block.setRead(true);
                Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
                    .disassemble(start, new AddressSet(start,
                        start.add(text.length - 1)));
                for (long offset = 0; offset + 4 <= text.length; offset += 8) {
                    Address entry = start.add(offset);
                    if (program.getListing().getInstructionAt(entry) != null
                        && program.getFunctionManager().getFunctionAt(entry) == null) {
                        program.getFunctionManager().createFunction(
                            "FUN_" + Long.toHexString(entry.getOffset()), entry,
                            new AddressSet(entry, entry.add(3)), SourceType.DEFAULT);
                    }
                }
                transaction.commit();
            }
            PilotRun run = runPilot(program);
            assertEquals(Esp32S3FunctionIdStatus.NO_MATCHES.code(), run.status());
            assertEquals(0, run.renamed(),
                "unrelated Xtensa code must never receive an automatic IDF name");
        } finally {
            program.release(consumer);
        }
    }

    @Test
    void versionEvidenceFromUnrelatedImageImportRejectsDatabase() throws Exception {
        Object consumer = new Object();
        ProgramDB program = loadImageBytes(freestandingImage(), consumer);
        PilotRun run = runPilot(program);
        assertEquals(Esp32S3FunctionIdStatus.VERSION_INCOMPATIBLE.code(),
            run.status());
        assertEquals(0, run.renamed());
    }

    @Test
    void restrictedDumpPilotRegressionIsDigestGatedAndHonest() throws Exception {
        Path dump = PROJECT.resolve("esp32s3_ctf_dump_4MB.bin");
        Assumptions.assumeTrue(Files.isRegularFile(dump),
            "restricted local fixture is intentionally absent from public CI");
        byte[] flash = Files.readAllBytes(dump);
        assertEquals(RESTRICTED_DUMP_SHA256, sha256(flash));
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("untrusted.dat", flash);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        Object consumer = new Object();
        ImporterSettings settings = new ImporterSettings(provider, "restricted-local",
            null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false), consumer,
            new MessageLog(), TaskMonitor.DUMMY);
        Program app = null;
        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            List<Program> programs = new ArrayList<>();
            results.forEach(loaded -> loaded.apply(domainObject -> programs.add(
                (Program) domainObject)));
            app = programs.stream()
                .filter(candidate -> candidate.getOptions(
                    EmbedraEsp32S3FunctionIdAnalyzer.APP_DESCRIPTION_OPTIONS)
                    .getString(EmbedraEsp32S3FunctionIdAnalyzer
                        .APP_DESCRIPTION_IDF_VERSION_KEY, "").length() > 0)
                .findFirst().orElse(programs.get(0));
            String recorded = app.getOptions(
                EmbedraEsp32S3FunctionIdAnalyzer.APP_DESCRIPTION_OPTIONS)
                .getString(EmbedraEsp32S3FunctionIdAnalyzer
                    .APP_DESCRIPTION_IDF_VERSION_KEY, "");
            PilotRun run = runPilot(app);
            System.out.println("RESTRICTED DUMP FID: recorded version='" + recorded
                + "' status=" + run.status() + " renamed=" + run.renamed()
                + " examined=" + run.examined());
            if (!"v6.0".equals(recorded)) {
                assertEquals(Esp32S3FunctionIdStatus.VERSION_INCOMPATIBLE.code(),
                    run.status());
                assertEquals(0, run.renamed());
            }
        }
    }

    @Test
    void repeatedPilotRunIsIdempotent() throws Exception {
        Object consumer = new Object();
        ProgramDB program = loadStrippedImage("embedra-fid-ref-app-a.bin", consumer);
        Map<Long, Set<String>> oracle = createOracleFunctions(program,
            "esp32s3-fid-reference-appa.symbols.json");
            PilotRun first = runPilot(program);
            Map<String, List<String>> afterFirst = naming(program);
            PilotRun second = runPilot(program);
            assertEquals(afterFirst, naming(program));
            assertEquals(705, first.renamed());
            assertEquals(26, first.ambiguous());
            assertEquals(Esp32S3FunctionIdStatus.AMBIGUOUS_MATCHES.code(),
                second.status());
            assertEquals(0, second.renamed());
            assertTrue(second.ambiguous() > 0);
    }

    @Test
    void independentRunsShareDeterministicPilotOutcomes() throws Exception {
        Object firstConsumer = new Object();
        Object secondConsumer = new Object();
        ProgramDB first = loadStrippedImage("embedra-fid-ref-app-a.bin",
            firstConsumer);
        createOracleFunctions(first, "esp32s3-fid-reference-appa.symbols.json");
        PilotRun firstRun = runPilot(first);
        Map<String, List<String>> firstNames = naming(first);
        releaseLoadedProgram(first);

        ProgramDB second = loadStrippedImage("embedra-fid-ref-app-a.bin",
            secondConsumer);
        createOracleFunctions(second, "esp32s3-fid-reference-appa.symbols.json");
        PilotRun secondRun = runPilot(second);
        Map<String, List<String>> secondNames = naming(second);
        assertEquals(firstRun.status(), secondRun.status());
        assertEquals(firstRun.renamed(), secondRun.renamed());
        assertEquals(firstRun.examined(), secondRun.examined());
        assertEquals(firstNames.keySet(), secondNames.keySet());
        for (String entry : firstNames.keySet()) {
            assertEquals(firstNames.get(entry), secondNames.get(entry),
                "deterministic pilot output at " + entry);
        }
    }

    private record PilotRun(String status, String evidence, int renamed, int ambiguous,
            int examined) {
    }

    private static PilotRun runPilot(Program program) {
        Options options = program.getOptions(
            EmbedraEsp32S3FunctionIdAnalyzer.OPTIONS_NODE);
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Configure pilot Function ID paths")) {
            options.setString(EmbedraEsp32S3FunctionIdAnalyzer.DATABASE_PATH_OPTION,
                fidPath(DATABASE_FILE).toString());
            options.setString(
                EmbedraEsp32S3FunctionIdAnalyzer.DESCRIPTOR_PATH_OPTION,
                fidPath(DESCRIPTOR_FILE).toString());
            transaction.commit();
        }
        EmbedraEsp32S3FunctionIdAnalyzer analyzer =
            new EmbedraEsp32S3FunctionIdAnalyzer();
        boolean completed = true;
        PrintStream originalOut = System.out;
        try {
            System.setOut(new PrintStream(OutputStream.nullOutputStream()));
            completed = analyzer.added(program, program.getMemory().getExecuteSet(),
                TaskMonitor.DUMMY, new MessageLog());
        }
        catch (ghidra.util.exception.CancelledException exception) {
            throw new IllegalStateException(exception);
        }
        finally {
            System.setOut(originalOut);
        }
        assertTrue(completed);
        return new PilotRun(
            options.getString(EmbedraEsp32S3FunctionIdAnalyzer.STATUS_CODE_KEY, ""),
            options.getString(EmbedraEsp32S3FunctionIdAnalyzer.VERSION_EVIDENCE_KEY,
                ""),
            options.getInt(EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_RENAMED_KEY, -1),
            options.getInt(EmbedraEsp32S3FunctionIdAnalyzer.AMBIGUOUS_FUNCTIONS_KEY,
                -1),
            options.getInt(EmbedraEsp32S3FunctionIdAnalyzer.FUNCTIONS_EXAMINED_KEY,
                -1));
    }

    private static ProgramDB loadStrippedImage(String name, Object consumer)
            throws Exception {
        return loadImageBytes(image(name), consumer);
    }

    private static ProgramDB loadImageBytes(byte[] bytes, Object consumer)
            throws Exception {
        EspApplicationImageLoader loader = new EspApplicationImageLoader();
        ByteArrayProvider provider = new ByteArrayProvider("reference.bin", bytes);
        LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
        ImporterSettings settings = new ImporterSettings(provider, "reference.bin",
            null, "/", false, spec,
            loader.getDefaultOptions(provider, spec, null, false, false), consumer,
            new MessageLog(), TaskMonitor.DUMMY);
        LoadResults<? extends DomainObject> results = loader.load(settings);
        Program[] captured = new Program[1];
        results.getPrimary().apply(domainObject -> captured[0] = (Program) domainObject);
        Object retention = new Object();
        captured[0].addConsumer(retention);
        LOADED_PROGRAMS.add(new RetainedProgram(captured[0], retention));
        results.close();
        return (ProgramDB) captured[0];
    }

    private static void releaseLoadedProgram(Program program) {
        LOADED_PROGRAMS.removeIf(loaded -> {
            if (loaded.program() == program) {
                loaded.program().release(loaded.consumer());
                return true;
            }
            return false;
        });
    }

    private static Map<Long, Set<String>> createOracleFunctions(Program program,
            String oracleName) throws Exception {
        Map<Long, Set<String>> oracle = new HashMap<>();
        for (Map<String, Object> symbol : symbolMaps(oracleName)) {
            oracle.computeIfAbsent(((Number) symbol.get("address")).longValue(),
                key -> new TreeSet<>()).add((String) symbol.get("name"));
        }
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Create oracle functions")) {
            Disassembler disassembler = Disassembler.getDisassembler(program,
                TaskMonitor.DUMMY, null);
            for (Map.Entry<Long, Set<String>> entry : oracle.entrySet()) {
                Address start = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(entry.getKey());
                MemoryBlock block = program.getMemory().getBlock(start);
                if (block == null || !block.isExecute()) {
                    continue;
                }
                long size = symbolSize(oracleName, entry.getKey());
                Address end = start.add(Math.max(size - 1, 3));
                AddressSet body = new AddressSet(start, end);
                disassembler.disassemble(start, body);
                if (program.getFunctionManager().getFunctionAt(start) == null) {
                    program.getFunctionManager().createFunction(
                        "FUN_" + Long.toHexString(start.getOffset()), start, body,
                        SourceType.DEFAULT);
                }
            }
            transaction.commit();
        }
        return oracle;
    }

    private static long symbolSize(String oracleName, long address) throws Exception {
        for (Map<String, Object> symbol : symbolMaps(oracleName)) {
            if (((Number) symbol.get("address")).longValue() == address) {
                return Math.max(((Number) symbol.get("size")).longValue(), 4);
            }
        }
        return 4;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> symbolMaps(String oracleName)
            throws Exception {
        Object parsed;
        try (InputStream input = Files.newInputStream(PROJECT.resolve(
                "src/test/resources/oracles/esp32s3/fid/" + oracleName))) {
            parsed = StrictJsonParser.parse(input.readAllBytes(),
                ParserLimits.defaults(), CancellationToken.none());
        }
        Map<String, Object> root = (Map<String, Object>) parsed;
        return (List<Map<String, Object>>) root.get("functions");
    }

    private static void assertNoFalseRenames(Program program,
            Map<Long, Set<String>> oracle) {
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (function.getSymbol().getSource() == SourceType.ANALYSIS) {
                Set<String> allowed = oracle.getOrDefault(
                    function.getEntryPoint().getOffset(), Set.of());
                if (function.getName().startsWith("FID_conflict:")) {
                    assertTrue(function.getComment() != null
                            && function.getComment().contains("Multiple Matches"),
                        "Ghidra conflict labels must retain explicit multiple-match evidence");
                }
                else if (!allowed.contains(function.getName())) {
                    boolean commonBase = allowed.stream().anyMatch(candidate ->
                        candidate.startsWith(function.getName() + "_")
                            && candidate.substring(function.getName().length() + 1)
                                .matches("[a-z0-9]+(?:_[a-z0-9]+)*"));
                    assertTrue(commonBase,
                        "FID rename at " + function.getEntryPoint() + " must match a"
                            + " reference symbol or its literal underscore-delimited"
                            + " common base; reference names "
                            + allowed + ", applied name " + function.getName());
                }
            }
        }
    }

    private static String namedOracleFunction(Program program,
            Map<Long, Set<String>> oracle, String symbolName) {
        for (Map.Entry<Long, Set<String>> entry : oracle.entrySet()) {
            if (entry.getValue().contains(symbolName)) {
                Function function = program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(entry.getKey()));
                assertNotNull(function, "oracle function " + symbolName);
                return function.getName();
            }
        }
        throw new AssertionError("symbol " + symbolName + " absent from oracle");
    }

    private static Map<String, List<String>> naming(Program program) {
        Map<String, List<String>> state = new LinkedHashMap<>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            state.put(function.getEntryPoint().toString(),
                Arrays.asList(function.getName(),
                    function.getSymbol().getSource().name(),
                    String.valueOf(function.getComment())));
        }
        return state;
    }

    private static Esp32S3FidProvenance parseDescriptor() throws Exception {
        return Esp32S3FidProvenance.parse(
            Files.readAllBytes(fidPath(DESCRIPTOR_FILE)),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static Path fidPath(String name) {
        return PROJECT.resolve("fid/esp32s3/" + name);
    }

    private static byte[] image(String name) throws IOException {
        return fixture("/fixtures/esp32s3/fid/" + name);
    }

    private static byte[] freestandingImage() throws IOException {
        return fixture("/fixtures/esp32s3/esp32s3-freestanding-minimal.bin");
    }

    private static byte[] fixture(String resource) throws IOException {
        try (InputStream input = Esp32S3FunctionIdPilotFixturesTest.class
                .getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("Missing fixture " + resource);
            }
            return input.readAllBytes();
        }
    }

    private static String sha256(Path path) throws Exception {
        return sha256(Files.readAllBytes(path));
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
