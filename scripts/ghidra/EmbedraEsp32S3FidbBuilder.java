/*
 * Build a provenance-verified ESP32-S3 ESP-IDF Function ID database using
 * Ghidra's official ingest, then emit the matching Embedra provenance
 * descriptor next to it. Typical invocation from the generator script:
 *
 *   analyzeHeadless <projDir> embedra_fid -import <reference.elf> \
 *       -language Xtensa:LE:32:esp32s3 -cspec default \
 *       -scriptPath scripts/ghidra -postScript EmbedraEsp32S3FidbBuilder.java \
 *       -scriptArgs -out <out.fidb> -variant <v> -elfsha <hex> -bin <name.bin> \
 *       -binsha <hex> -sdkconfigsha <hex> -components <file> -exclusions <file>
 *
 * -components lists audited components as "name<TAB>license" lines; -exclusions
 * lists toolchain archive symbol names that must never enter the database.
 */
//Build a provenance-verified ESP32-S3 ESP-IDF Function ID database
//@category Embedra
import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

public class EmbedraEsp32S3FidbBuilder extends GhidraScript {
    private static final String IDF_REVISION =
        "662a3be354759d9487bf4b1a629fadb766cb1800";

    private static final String IDF_VERSION = "v6.0";

    private static final String TOOLCHAIN =
        "xtensa-esp-elf esp-15.2.0_20251204 (gcc 15.2.0, binutils 2.45)";

    private static final String GENERATOR_COMMAND =
        "./scripts/generate-esp32s3-fid-ref.sh";

    private static final String LIBRARY_FAMILY = "ESP-IDF";

    @Override
    protected void run() throws Exception {
        String elfSha = require("-elfsha");
        String binSha = require("-binsha");
        String sdkconfigSha = require("-sdkconfigsha");
        String outPath = require("-out");
        String variant = require("-variant");
        List<String[]> components = readComponents(require("-components"));
        Set<String> exclusions = readLines(require("-exclusions"));

        if (!currentProgram.getLanguageID().getIdAsString().equals("Xtensa:LE:32:esp32s3")
            || !currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()
                .equals("default")) {
            throw new IllegalStateException("FIDB builder must run in"
                + " Xtensa:LE:32:esp32s3 default but program is "
                + currentProgram.getLanguageID().getIdAsString() + " / "
                + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        }

        File database = new File(outPath).getAbsoluteFile();
        if (database.exists()) {
            database.delete();
        }
        FidFileManager manager = FidFileManager.getInstance();
        manager.createNewFidDatabase(database);
        FidFile fidFile = null;
        for (FidFile candidate : manager.getFidFiles()) {
            if (candidate.getPath().equals(database.getAbsolutePath())) {
                fidFile = candidate;
            }
        }
        if (fidFile == null) {
            throw new IllegalStateException("Ghidra did not register the new database");
        }
        int added;
        DomainFile sourceFile = currentProgram.getDomainFile();
        if (sourceFile.getFileID() == null) {
            // Headless only saves the analyzed program after post-scripts, but the
            // official FID ingest opens programs through their persisted DomainFile.
            sourceFile.save(monitor);
        }
        try (FidDB db = fidFile.getFidDB(true)) {
            FidService service = new FidService();
            List<DomainFile> programs = new ArrayList<>();
            programs.add(sourceFile);
            Predicate<Pair<Function, FidHashQuad>> keepEspIdfOnly =
                pair -> !exclusions.contains(pair.first.getName());
            String libraryVersion = IDF_VERSION + "-" + IDF_REVISION.substring(0, 12);
            FidPopulateResult result = service.createNewLibraryFromPrograms(db,
                LIBRARY_FAMILY, libraryVersion, variant, programs, keepEspIdfOnly,
                new LanguageID("Xtensa:LE:32:esp32s3"), List.of(), List.of(), monitor);
            added = result.getTotalAdded();
            db.saveDatabase("Embedra ESP32-S3 FIDB build", monitor);
            printf("FIDB variant=%s added=%d excluded=%d attempted=%d%n", variant, added,
                result.getTotalExcluded(), result.getTotalAttempted());
        }
        finally {
            manager.removeUserFile(fidFile);
        }
        writeDescriptor(database.toPath(), outPath + ".json", elfSha, binSha, sdkconfigSha,
            variant, added, components);
        monitor.setMessage("ESP32-S3 FIDB and descriptor written");
    }

    private void writeDescriptor(Path database, String descriptorPath, String elfSha,
            String binSha, String sdkconfigSha, String variant, int added,
            List<String[]> components) throws IOException {
        StringBuilder audit = new StringBuilder();
        for (int i = 0; i < components.size(); i++) {
            String[] entry = components.get(i);
            audit.append("    {\"name\": \"").append(entry[0])
                .append("\", \"license\": \"").append(entry[1])
                .append("\", \"redistribution\": \"ALLOWED\"}");
            if (i + 1 < components.size()) {
                audit.append(",\n");
            }
        }
        String json = """
            {
              "schemaId": "urn:embedra:schema:esp32s3-fidb-provenance:1",
              "artifactId": "esp32s3-esp-idf-v6.0-refapp-os",
              "targetId": "esp32s3",
              "chipId": 9,
              "languageId": "Xtensa:LE:32:esp32s3",
              "compilerSpecId": "default",
              "idfVersion": "%s",
              "idfRevision": "%s",
              "toolchain": "%s",
              "optimization": "Os",
              "sdkconfigSha256": "%s",
              "referenceElfSha256": "%s",
              "strippedImageSha256": "%s",
              "fidbSha256": "%s",
              "functionCount": %d,
              "generatorCommand": "%s",
              "ghidraVersion": "12.1.3",
              "libraryFamily": "%s",
              "libraryVersion": "%s",
              "libraryVariant": "%s",
              "components": [
            %s
              ],
              "redistribution": "ALLOWED"
            }
            """.formatted(IDF_VERSION, IDF_REVISION, TOOLCHAIN, sdkconfigSha, elfSha,
                binSha, sha256(database), added, GENERATOR_COMMAND, LIBRARY_FAMILY,
                IDF_VERSION + "-" + IDF_REVISION.substring(0, 12), variant,
                audit.toString());
        Files.writeString(Path.of(descriptorPath), json, StandardCharsets.UTF_8);
        printf("FIDB descriptor written to %s%n", descriptorPath);
    }

    private List<String[]> readComponents(String path) throws IOException {
        List<String[]> result = new ArrayList<>();
        for (String line : readLines(path)) {
            String[] parts = line.split("\t", 2);
            if (parts.length == 2 && !parts[0].isBlank() && !parts[1].isBlank()) {
                result.add(parts);
            }
        }
        if (result.isEmpty()) {
            throw new IOException("Component audit produced no license entries");
        }
        return result;
    }

    private Set<String> readLines(String path) throws IOException {
        Set<String> result = new HashSet<>();
        for (String line : Files.readAllLines(Path.of(path), StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    private String require(String flag) {
        String[] args = getScriptArgs();
        for (int i = 0; i + 1 < args.length; i++) {
            if (flag.equals(args[i])) {
                return args[i + 1];
            }
        }
        throw new IllegalArgumentException("Missing required script argument: " + flag);
    }

    private static String sha256(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(Files.readAllBytes(path)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IOException(exception);
        }
    }
}
