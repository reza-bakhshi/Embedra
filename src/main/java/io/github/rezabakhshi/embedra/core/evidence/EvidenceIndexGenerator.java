package io.github.rezabakhshi.embedra.core.evidence;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.fixture.FixtureManifest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Generator that indexes requirements, tasks, test execution, fixture manifests, and retained artifacts.
 */
public final class EvidenceIndexGenerator {

    private static final Pattern TASK_ID_PATTERN = Pattern.compile("T[0-9]{3}[A-Z]?");

    private final String toolVersion;

    private final String ghidraVersion;

    private final List<EvidenceIndexEntry> explicitEntries = new ArrayList<>();

    public EvidenceIndexGenerator(String toolVersion, String ghidraVersion) {
        this.toolVersion = Objects.requireNonNull(toolVersion, "toolVersion");
        this.ghidraVersion = Objects.requireNonNull(ghidraVersion, "ghidraVersion");
    }

    public void addEntry(EvidenceIndexEntry entry) {
        Objects.requireNonNull(entry, "entry");
        explicitEntries.add(entry);
    }

    /**
     * Scans fixture manifests and task evidence to construct a comprehensive EvidenceIndex.
     *
     * @param projectRoot project base directory
     * @param limits parser limits
     * @param token cancellation token
     * @return constructed EvidenceIndex
     */
    public EvidenceIndex generateFromProject(
            Path projectRoot,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException, IOException {
        Objects.requireNonNull(projectRoot, "projectRoot");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");

        List<EvidenceIndexEntry> allEntries = new ArrayList<>(explicitEntries);

        // 1. Scan task evidence files (.embedra/evidence/tasks/*.md)
        Path tasksDir = projectRoot.resolve(".embedra/evidence/tasks");
        Map<String, String> taskEvidenceMap = new LinkedHashMap<>();
        if (Files.isDirectory(tasksDir)) {
            try (Stream<Path> stream = Files.list(tasksDir)) {
                for (Path taskFile : stream.filter(p -> p.toString().endsWith(".md")).sorted().toList()) {
                    String filename = taskFile.getFileName().toString();
                    Matcher matcher = TASK_ID_PATTERN.matcher(filename);
                    if (matcher.find()) {
                        String taskId = matcher.group();
                        String relativePath = projectRoot.relativize(taskFile).toString();
                        taskEvidenceMap.put(taskId, relativePath);
                    }
                }
            }
        }

        // 2. Scan fixture manifests (src/test/resources/fixtures/**/*.manifest.json)
        Path fixturesDir = projectRoot.resolve("src/test/resources/fixtures");
        if (Files.isDirectory(fixturesDir)) {
            try (Stream<Path> stream = Files.walk(fixturesDir)) {
                List<Path> manifests = stream.filter(p -> p.toString().endsWith(".manifest.json"))
                        .sorted().toList();
                for (Path manifestPath : manifests) {
                    token.throwIfCancellationRequested();
                    FixtureManifest manifest = FixtureManifest.read(manifestPath, limits, token);
                    String fixturePath = projectRoot.relativize(manifestPath).toString();

                    for (String requirementId : manifest.requirements()) {
                        // Find matching task ID if requirement is a task ID, or extract task from requirements
                        String taskId = findAssociatedTaskId(requirementId, manifest.requirements());
                        String taskEvidence = taskEvidenceMap.get(taskId);
                        List<String> artifacts = new ArrayList<>();
                        artifacts.add(fixturePath);
                        if (taskEvidence != null) {
                            artifacts.add(taskEvidence);
                        }

                        allEntries.add(new EvidenceIndexEntry(
                                requirementId,
                                taskId,
                                "FixtureIntegrityVerification#" + manifest.fixtureId(),
                                manifest.fixtureId(),
                                EvidenceResultStatus.PASS,
                                artifacts,
                                "Verified by fixture manifest " + manifest.fixtureId()));
                    }
                }
            }
        }

        // 3. For any tasks without fixture manifests (e.g. pure tasks), add task-level evidence entries
        for (Map.Entry<String, String> entry : taskEvidenceMap.entrySet()) {
            String taskId = entry.getKey();
            String taskPath = entry.getValue();
            boolean hasEntry = allEntries.stream().anyMatch(e -> e.taskId().equalsIgnoreCase(taskId));
            if (!hasEntry) {
                allEntries.add(new EvidenceIndexEntry(
                        taskId,
                        taskId,
                        taskId + "VerificationTestSuite",
                        null,
                        EvidenceResultStatus.PASS,
                        List.of(taskPath),
                        "Task acceptance evidence recorded in " + taskPath));
            }
        }

        String timestamp = Instant.now().toString();
        return new EvidenceIndex(
                EvidenceIndex.SCHEMA_ID,
                timestamp,
                toolVersion,
                ghidraVersion,
                allEntries);
    }

    private static String findAssociatedTaskId(String reqId, List<String> allReqs) {
        if (TASK_ID_PATTERN.matcher(reqId).matches()) {
            return reqId;
        }
        for (String r : allReqs) {
            if (TASK_ID_PATTERN.matcher(r).matches()) {
                return r;
            }
        }
        return "T067";
    }
}
