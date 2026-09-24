package io.github.rezabakhshi.embedra.ghidra.esp;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.feature.fid.cmd.ApplyFidEntriesCommand;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.service.FidSearchResult;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.service.MatchNameAnalysis;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.esp.Esp32S3FidProvenance;
import io.github.rezabakhshi.embedra.analyzers.esp.Esp32S3FunctionIdEvidence;
import io.github.rezabakhshi.embedra.analyzers.esp.Esp32S3FunctionIdOutcome;
import io.github.rezabakhshi.embedra.analyzers.esp.Esp32S3FunctionIdStatus;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Explicit, opt-in ESP32-S3 ESP-IDF Function ID naming for stripped images.
 *
 * <p>This analyzer is separate from Ghidra's generic "Function ID" analyzer, whose
 * presence in the auto-analysis list is never evidence that a database ran. It runs
 * only when the user explicitly enables it and configures both a pilot database and
 * its matching provenance descriptor through deterministic program options. Ghidra
 * 12.1.3 would accept any Xtensa little-endian 32-bit database by processor family,
 * width, and endianness; that family-level applicability is not match validity, so
 * this path additionally requires the database library record and descriptor to
 * declare the exact {@code Xtensa:LE:32:esp32s3} variant.</p>
 *
 * <p>Attachment is run-scoped: a database not already attached to Ghidra is attached
 * only for the duration of this run and detached afterwards, preserving whatever the
 * user had configured. User-defined and imported names are never overwritten; Ghidra's
 * conflict-preserving apply policy is used unchanged.</p>
 */
public final class EmbedraEsp32S3FunctionIdAnalyzer extends AbstractAnalyzer {
    public static final String OPTIONS_NODE = "Embedra ESP32-S3 Function ID";

    public static final String DATABASE_PATH_OPTION = "Function ID Database Path";

    public static final String DESCRIPTOR_PATH_OPTION = "Provenance Descriptor Path";

    public static final String STATUS_CODE_KEY = "Status Code";

    public static final String FUNCTIONS_EXAMINED_KEY = "Functions Examined";

    public static final String CANDIDATE_FUNCTIONS_KEY = "Candidate Functions";

    public static final String FUNCTIONS_RENAMED_KEY = "Functions Renamed";

    public static final String AMBIGUOUS_FUNCTIONS_KEY = "Ambiguous Functions";

    public static final String VERSION_EVIDENCE_KEY = "ESP-IDF Version Evidence";

    public static final String DATABASE_SHA256_KEY = "Database SHA-256";

    public static final String LIBRARY_IDENTITY_KEY = "Library Identity";

    public static final String TARGET_LANGUAGE_KEY = "Target Language";

    public static final String IDF_IDENTITY_KEY = "ESP-IDF Identity";

    public static final String TOOLCHAIN_KEY = "Toolchain";

    public static final String OPTIMIZATION_KEY = "Optimization";

    public static final String GENERATOR_COMMAND_KEY = "Generator Command";

    public static final String APP_DESCRIPTION_OPTIONS = "Embedra ESP32-S3 App Description";

    public static final String APP_DESCRIPTION_IDF_VERSION_KEY = "IDF Version";

    private static final String NAME = "Embedra ESP32-S3 Function ID";

    private static final String DESCRIPTION =
        "Names stripped ESP-IDF ESP32-S3 functions from an explicitly attached, "
            + "provenance-verified pilot database (off by default)";

    private static final String ESP32S3_LANGUAGE_ID = "Xtensa:LE:32:esp32s3";

    public EmbedraEsp32S3FunctionIdAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS);
        setDefaultEnablement(false);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return ESP32S3_LANGUAGE_ID.equals(program.getLanguageID().getIdAsString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        try {
            return analyze(program, set, monitor, log);
        }
        catch (DiagnosticException exception) {
            if (exception.diagnostic().code() == DiagnosticCode.CANCELLED) {
                recordRefused(program, Esp32S3FunctionIdStatus.CANCELLED,
                    "cancelled before analysis; no changes were committed");
                log.appendMsg(NAME, Esp32S3FunctionIdStatus.CANCELLED.code()
                    + ": Function ID run cancelled; no partial state was committed");
                throw new CancelledException("Embedra Function ID cancelled");
            }
            return refuse(program, log, Esp32S3FunctionIdStatus.PROVENANCE_INVALID,
                exception.diagnostic().code().id() + ": " + exception.getMessage());
        }
        catch (RunFailedException failure) {
            recordRefused(program, Esp32S3FunctionIdStatus.RUN_FAILED, failure.getMessage());
            log.appendMsg(NAME, Esp32S3FunctionIdStatus.RUN_FAILED.code() + ": "
                + failure.getMessage());
            return false;
        }
    }

    private boolean analyze(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException, RunFailedException, DiagnosticException {
        Options node = program.getOptions(OPTIONS_NODE);
        String databasePath = node.getString(DATABASE_PATH_OPTION, "");
        String descriptorPath = node.getString(DESCRIPTOR_PATH_OPTION, "");
        if (databasePath.isBlank() || !Files.isRegularFile(Path.of(databasePath))) {
            return refuse(program, log, Esp32S3FunctionIdStatus.DATABASE_ABSENT,
                "No ESP32-S3 Function ID database is configured for this program. Ghidra's"
                    + " generic 'Function ID' analyzer entry is unrelated and proves no run."
                    + " Configure the Embedra database and provenance descriptor options"
                    + " explicitly to opt in.");
        }
        Esp32S3FidProvenance provenance;
        if (descriptorPath.isBlank() || !Files.isRegularFile(Path.of(descriptorPath))) {
            return refuse(program, log, Esp32S3FunctionIdStatus.PROVENANCE_INVALID,
                "A pilot database requires a provenance descriptor so target, ESP-IDF"
                    + " revision, toolchain, optimization, and licensing remain visible.");
        }
        try {
            provenance = Esp32S3FidProvenance.parse(
                Files.readAllBytes(Path.of(descriptorPath)), ParserLimits.defaults(),
                cancellation(monitor));
        }
        catch (IOException exception) {
            return refuse(program, log, Esp32S3FunctionIdStatus.PROVENANCE_INVALID,
                "Provenance descriptor could not be read: " + exception.getMessage());
        }
        if (!provenance.languageId().equals(program.getLanguageID().getIdAsString())) {
            return refuse(program, log, Esp32S3FunctionIdStatus.TARGET_INCOMPATIBLE,
                "The descriptor language " + provenance.languageId() + " does not match the"
                    + " program language " + program.getLanguageID().getIdAsString()
                    + "; the exact ESP32-S3 variant is required");
        }
        String databaseDigest;
        try {
            databaseDigest = sha256(Path.of(databasePath));
        }
        catch (IOException | NoSuchAlgorithmException exception) {
            return refuse(program, log,
                Esp32S3FunctionIdStatus.DATABASE_DIGEST_MISMATCH,
                "The configured Function ID database could not be read: "
                    + exception.getMessage());
        }
        if (!databaseDigest.equals(provenance.fidbSha256())) {
            return refuse(program, log, Esp32S3FunctionIdStatus.DATABASE_DIGEST_MISMATCH,
                "Database SHA-256 " + databaseDigest + " does not match the descriptor "
                    + provenance.fidbSha256() + "; refusing to name functions from a"
                    + " database whose build identity is unverified");
        }
        String recordedVersion = program.getOptions(APP_DESCRIPTION_OPTIONS)
            .getString(APP_DESCRIPTION_IDF_VERSION_KEY, "");
        Esp32S3FunctionIdEvidence evidence;
        if (recordedVersion.isBlank()) {
            evidence = Esp32S3FunctionIdEvidence.UNCERTAIN;
        }
        else if (!recordedVersion.equals(provenance.idfVersion())) {
            return refuse(program, log, Esp32S3FunctionIdStatus.VERSION_INCOMPATIBLE,
                "Program metadata records ESP-IDF " + recordedVersion + " but the database"
                    + " was generated from " + provenance.idfVersion() + " at revision "
                    + provenance.idfRevision() + "; candidate matches are not applied");
        }
        else {
            evidence = Esp32S3FunctionIdEvidence.CONFIRMED;
        }
        return attachAndRun(program, set, monitor, log, provenance, databaseDigest, evidence);
    }

    private boolean attachAndRun(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log, Esp32S3FidProvenance provenance, String databaseDigest,
            Esp32S3FunctionIdEvidence evidence) throws CancelledException, RunFailedException {
        FidFileManager manager = FidFileManager.getInstance();
        Path database = Path.of(program.getOptions(OPTIONS_NODE)
            .getString(DATABASE_PATH_OPTION, ""));
        FidFile fidFile = findRegistered(manager, database);
        boolean attachedHere = false;
        boolean refreshedPreexisting = false;
        boolean priorAttachedActive = true;
        if (fidFile == null) {
            fidFile = manager.addUserFidFile(database.toAbsolutePath().toFile());
            attachedHere = true;
        }
        if (fidFile == null) {
            return refuse(program, log, Esp32S3FunctionIdStatus.DATABASE_DIGEST_MISMATCH,
                "Ghidra could not open the configured ESP32-S3 Function ID database;"
                    + " it may have been created by an incompatible Ghidra version");
        }
        try {
            String mismatch = libraryMismatch(fidFile, provenance);
            if (mismatch != null) {
                return refuse(program, log, Esp32S3FunctionIdStatus.TARGET_INCOMPATIBLE,
                    mismatch);
            }
            List<FidFile> applicable = manager.getFidFiles().stream()
                .filter(FidFile::isActive)
                .filter(candidate -> supportsLanguageFamily(candidate,
                    program.getLanguage()))
                .toList();
            if (applicable.size() != 1 || !applicable.contains(fidFile)) {
                return refuse(program, log, Esp32S3FunctionIdStatus.DATABASE_CONFLICT,
                    "Ghidra searches every active Function ID database for this language. "
                        + "Found " + applicable.size() + " active applicable databases; "
                        + "enable the configured database and disable other applicable "
                        + "databases so every applied name is covered by its provenance.");
            }
            if (!new FidService().canProcess(program.getLanguage())) {
                if (fidFile.isInstalled()) {
                    return refuse(program, log,
                        Esp32S3FunctionIdStatus.DATABASE_DIGEST_MISMATCH,
                        "Ghidra's installed Function ID database has a stale language cache; "
                            + "restarting Ghidra is required before retrying this database");
                }
                // FidFile caches supported languages on first open. A database created
                // and populated in this same Ghidra session can have a stale empty cache.
                // Refresh only the configured file, then restore its prior attachment
                // state in the finally block.
                priorAttachedActive = fidFile.isActive();
                boolean restoreAttachment = !attachedHere;
                refreshedPreexisting = restoreAttachment;
                manager.removeUserFile(fidFile);
                fidFile = manager.addUserFidFile(database.toAbsolutePath().toFile());
                if (fidFile != null) {
                    fidFile.setActive(priorAttachedActive);
                }
                if (fidFile == null || !new FidService().canProcess(program.getLanguage())) {
                    return refuse(program, log,
                        Esp32S3FunctionIdStatus.DATABASE_DIGEST_MISMATCH,
                        "Ghidra did not accept the attached ESP32-S3 Function ID database"
                            + " for this language");
                }
                attachedHere = !restoreAttachment;
            }
            Esp32S3FunctionIdOutcome outcome;
            try {
                outcome = runWithinTransaction(program, set, monitor, provenance, evidence,
                    databaseDigest);
            }
            catch (CancelledException cancellation) {
                recordRefused(program, Esp32S3FunctionIdStatus.CANCELLED,
                    "Function ID run cancelled; every candidate change was rolled back");
                log.appendMsg(NAME, Esp32S3FunctionIdStatus.CANCELLED.code()
                    + ": Function ID run cancelled; no partial state was committed");
                throw cancellation;
            }
            log.appendMsg(NAME, outcome.status().code() + ": examined "
                + outcome.functionsExamined() + " functions, "
                + outcome.candidateFunctions() + " candidate, "
                + outcome.functionsRenamed() + " newly named, "
                + outcome.functionsAmbiguous() + " ambiguous (version evidence: "
                + outcome.evidence().map(Enum::name).orElse("none") + ")");
            if (evidence == Esp32S3FunctionIdEvidence.UNCERTAIN
                && outcome.functionsRenamed() > 0) {
                log.appendMsg(NAME, "UNCERTAIN: the program carries no validated ESP-IDF"
                    + " version metadata; applied names are candidates, not verified"
                    + " version matches");
            }
            return true;
        }
        finally {
            if (attachedHere) {
                manager.removeUserFile(fidFile);
            }
            else if (refreshedPreexisting) {
                // A pre-existing attachment refreshed for Ghidra's language cache.
                if (fidFile != null && findRegistered(manager, database) != null) {
                    manager.removeUserFile(fidFile);
                }
                FidFile restored = manager.addUserFidFile(database.toAbsolutePath().toFile());
                if (restored != null && !priorAttachedActive) {
                    restored.setActive(false);
                }
            }
        }
    }

    private Esp32S3FunctionIdOutcome runWithinTransaction(Program program, AddressSetView set,
            TaskMonitor monitor, Esp32S3FidProvenance provenance,
            Esp32S3FunctionIdEvidence evidence, String databaseDigest)
            throws CancelledException, RunFailedException {
        FidService service = new FidService();
        GhidraProgramTransaction transaction = GhidraProgramTransaction.start(program,
            "Embedra ESP32-S3 Function ID");
        try {
            monitor.checkCancelled();
            Map<Address, Set<String>> before = functionNaming(program);
            int examined;
            int candidates;
            int ambiguous;
            try (FidQueryService query = service.openFidQueryService(program.getLanguage(),
                    false)) {
                List<FidSearchResult> results = service.processProgram(program, query,
                    service.getDefaultScoreThreshold(), monitor);
                examined = results.size();
                candidates = 0;
                ambiguous = 0;
                for (FidSearchResult result : results) {
                    if (result.matches.isEmpty()) {
                        continue;
                    }
                    candidates++;
                    MatchNameAnalysis nameAnalysis = new MatchNameAnalysis();
                    nameAnalysis.analyzeNames(result.matches, program, monitor);
                    if (nameAnalysis.getMostOptimisticCount() > 1) {
                        ambiguous++;
                    }
                }
            }
            catch (IOException | VersionException exception) {
                throw new RunFailedException("Ghidra could not query the attached ESP32-S3"
                    + " Function ID database: " + exception.getMessage());
            }
            monitor.checkCancelled();
            ApplyFidEntriesCommand command = new ApplyFidEntriesCommand(set,
                service.getDefaultScoreThreshold(), service.getDefaultMultiNameThreshold(),
                false, true);
            if (!command.applyTo(program, monitor)) {
                if (monitor.isCancelled()) {
                    throw new CancelledException("Embedra Function ID cancelled");
                }
                throw new RunFailedException("Ghidra's Function ID apply reported an"
                    + " incomplete run; no changes were committed");
            }
            if (monitor.isCancelled()) {
                throw new CancelledException("Embedra Function ID cancelled");
            }
            int renamed = countRenamed(before, functionNaming(program));
            Esp32S3FunctionIdOutcome outcome = Esp32S3FunctionIdOutcome.classify(evidence,
                examined, candidates, renamed, ambiguous);
            recordOutcome(program, provenance, databaseDigest, outcome);
            transaction.commit();
            return outcome;
        }
        finally {
            transaction.close();
        }
    }

    private static int countRenamed(Map<Address, Set<String>> before,
            Map<Address, Set<String>> after) {
        int renamed = 0;
        for (Map.Entry<Address, Set<String>> entry : after.entrySet()) {
            Set<String> previous = before.get(entry.getKey());
            if (previous != null && !previous.equals(entry.getValue())) {
                renamed++;
            }
        }
        return renamed;
    }

    private static Map<Address, Set<String>> functionNaming(Program program) {
        Map<Address, Set<String>> snapshot = new LinkedHashMap<>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            Set<String> names = new TreeSet<>();
            for (Symbol symbol : program.getSymbolTable().getSymbols(
                    function.getEntryPoint())) {
                if (symbol.getSource() != SourceType.DEFAULT) {
                    names.add(symbol.getName());
                }
            }
            snapshot.put(function.getEntryPoint(), names);
        }
        return snapshot;
    }

    private static String libraryMismatch(FidFile fidFile, Esp32S3FidProvenance provenance) {
        try (FidDB database = fidFile.getFidDB(false)) {
            List<LibraryRecord> libraries = database.getAllLibraries();
            if (libraries.isEmpty()) {
                return "The attached database contains no library";
            }
            for (LibraryRecord library : libraries) {
                if (provenance.libraryFamily().equals(library.getLibraryFamilyName())
                    && provenance.libraryVersion().equals(library.getLibraryVersion())
                    && provenance.libraryVariant().equals(library.getLibraryVariant())
                    && provenance.languageId().equals(
                        library.getGhidraLanguageID().getIdAsString())
                    && provenance.compilerSpecId().equals(
                        library.getGhidraCompilerSpecID().getIdAsString())) {
                    return null;
                }
            }
            return "No attached library declares the descriptor identity "
                + provenance.identity() + " for " + provenance.languageId()
                + " (Ghidra would still apply it by Xtensa family; that applicability is"
                + " not match validity)";
        }
        catch (IOException | VersionException exception) {
            return "The attached database could not be opened: " + exception.getMessage();
        }
    }

    private static FidFile findRegistered(FidFileManager manager, Path database) {
        String absolute = database.toAbsolutePath().toString();
        return manager.getFidFiles().stream()
            .filter(candidate -> candidate.getPath().equals(absolute))
            .findFirst().orElse(null);
    }

    private static boolean supportsLanguageFamily(FidFile file, Language language) {
        try (FidDB database = file.getFidDB(false)) {
            LanguageDescription target = language.getLanguageDescription();
            for (LibraryRecord library : database.getAllLibraries()) {
                try {
                    LanguageDescription candidate = DefaultLanguageService.getLanguageService()
                        .getLanguage(library.getGhidraLanguageID()).getLanguageDescription();
                    if (candidate.getProcessor().compareTo(target.getProcessor()) == 0
                        && candidate.getSize() == target.getSize()
                        && candidate.getInstructionEndian() == target.getInstructionEndian()) {
                        return true;
                    }
                }
                catch (LanguageNotFoundException ignored) {
                    // An unavailable language cannot supply a match for this program.
                }
            }
            return false;
        }
        catch (IOException | VersionException exception) {
            // Fail closed: an unreadable active database may otherwise contribute names.
            return true;
        }
    }

    private static CancellationToken cancellation(TaskMonitor monitor) {
        return monitor::isCancelled;
    }

    private static String sha256(Path path) throws IOException, NoSuchAlgorithmException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(path)));
    }

    private boolean refuse(Program program, MessageLog log, Esp32S3FunctionIdStatus status,
            String message) {
        recordRefused(program, status, message);
        log.appendMsg(NAME, status.code() + ": " + message);
        return true;
    }

    private static void recordRefused(Program program, Esp32S3FunctionIdStatus status,
            String reason) {
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(program,
                "Record ESP32-S3 Function ID status")) {
            Options options = program.getOptions(OPTIONS_NODE);
            options.setString(STATUS_CODE_KEY, status.code());
            options.setInt(FUNCTIONS_EXAMINED_KEY, 0);
            options.setInt(CANDIDATE_FUNCTIONS_KEY, 0);
            options.setInt(FUNCTIONS_RENAMED_KEY, 0);
            options.setInt(AMBIGUOUS_FUNCTIONS_KEY, 0);
            options.setString(VERSION_EVIDENCE_KEY, "");
            options.setString(DATABASE_SHA256_KEY, "");
            options.setString(LIBRARY_IDENTITY_KEY, "");
            options.setString(TARGET_LANGUAGE_KEY, "");
            options.setString(IDF_IDENTITY_KEY, "");
            options.setString(TOOLCHAIN_KEY, "");
            options.setString(OPTIMIZATION_KEY, "");
            options.setString(GENERATOR_COMMAND_KEY, "");
            transaction.commit();
        }
    }

    private static void recordOutcome(Program program, Esp32S3FidProvenance provenance,
            String databaseDigest, Esp32S3FunctionIdOutcome outcome) {
        Options options = program.getOptions(OPTIONS_NODE);
        options.setString(STATUS_CODE_KEY, outcome.status().code());
        options.setInt(FUNCTIONS_EXAMINED_KEY, outcome.functionsExamined());
        options.setInt(CANDIDATE_FUNCTIONS_KEY, outcome.candidateFunctions());
        options.setInt(FUNCTIONS_RENAMED_KEY, outcome.functionsRenamed());
        options.setInt(AMBIGUOUS_FUNCTIONS_KEY, outcome.functionsAmbiguous());
        options.setString(VERSION_EVIDENCE_KEY,
            outcome.evidence().map(Enum::name).orElse(""));
        options.setString(DATABASE_SHA256_KEY, databaseDigest);
        options.setString(LIBRARY_IDENTITY_KEY, provenance.identity());
        options.setString(TARGET_LANGUAGE_KEY, provenance.languageId());
        options.setString(IDF_IDENTITY_KEY,
            provenance.idfVersion() + "@" + provenance.idfRevision());
        options.setString(TOOLCHAIN_KEY, provenance.toolchain());
        options.setString(OPTIMIZATION_KEY, provenance.optimization());
        options.setString(GENERATOR_COMMAND_KEY, provenance.generatorCommand());
    }

    /** Ghidra could not complete a verified Function ID run; nothing was committed. */
    private static final class RunFailedException extends Exception {
        private static final long serialVersionUID = 1L;

        private RunFailedException(String message) {
            super(message);
        }
    }
}
