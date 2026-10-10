package io.github.rezabakhshi.embedra.core.evidence;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.fixture.FixtureManifestJsonParser;
import io.github.rezabakhshi.embedra.core.report.CanonicalJson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Machine-readable index tying specification requirements and tasks to test execution and artifacts (SPEC-12, AN-015).
 */
public record EvidenceIndex(
        String schemaId,
        String generatedAt,
        String toolVersion,
        String ghidraVersion,
        List<EvidenceIndexEntry> entries) {

    public static final String SCHEMA_ID = "urn:embedra:schema:evidence-index:1";

    public EvidenceIndex {
        Objects.requireNonNull(schemaId, "schemaId");
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new IllegalArgumentException("Unsupported evidence index schema: " + schemaId);
        }
        Objects.requireNonNull(generatedAt, "generatedAt");
        Objects.requireNonNull(toolVersion, "toolVersion");
        Objects.requireNonNull(ghidraVersion, "ghidraVersion");
        Objects.requireNonNull(entries, "entries");

        List<EvidenceIndexEntry> sortedEntries = new ArrayList<>(entries);
        sortedEntries.sort(Comparator
                .comparing(EvidenceIndexEntry::requirementId)
                .thenComparing(EvidenceIndexEntry::taskId)
                .thenComparing(EvidenceIndexEntry::testName));
        entries = List.copyOf(sortedEntries);
    }

    public List<EvidenceIndexEntry> findEntriesForRequirement(String requirementId) {
        if (requirementId == null) {
            return List.of();
        }
        return entries.stream()
                .filter(e -> e.requirementId().equalsIgnoreCase(requirementId))
                .toList();
    }

    public List<EvidenceIndexEntry> findEntriesForTask(String taskId) {
        if (taskId == null) {
            return List.of();
        }
        return entries.stream()
                .filter(e -> e.taskId().equalsIgnoreCase(taskId))
                .toList();
    }

    public List<EvidenceIndexEntry> findEntriesForFixture(String fixtureId) {
        if (fixtureId == null) {
            return List.of();
        }
        return entries.stream()
                .filter(e -> fixtureId.equalsIgnoreCase(e.fixtureId()))
                .toList();
    }

    public Set<String> allCoveredRequirements() {
        Set<String> reqs = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (EvidenceIndexEntry entry : entries) {
            reqs.add(entry.requirementId());
        }
        return Collections.unmodifiableSet(reqs);
    }

    public Set<String> allCoveredTasks() {
        Set<String> tasks = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (EvidenceIndexEntry entry : entries) {
            tasks.add(entry.taskId());
        }
        return Collections.unmodifiableSet(tasks);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaId", schemaId);
        map.put("generatedAt", generatedAt);
        map.put("toolVersion", toolVersion);
        map.put("ghidraVersion", ghidraVersion);

        List<Map<String, Object>> entryMaps = new ArrayList<>();
        for (EvidenceIndexEntry entry : entries) {
            entryMaps.add(entry.toMap());
        }
        map.put("entries", entryMaps);
        return map;
    }

    public String toJson() {
        return CanonicalJson.write(toMap());
    }

    public static EvidenceIndex parse(
            byte[] bytes,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Object parsed = FixtureManifestJsonParser.parse(bytes, limits, token);
        if (!(parsed instanceof Map<?, ?> map)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.EVIDENCE_INDEX_INVALID,
                    "Evidence index root must be a JSON object"));
        }
        return fromMap(map);
    }

    public static EvidenceIndex read(
            Path path,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException, IOException {
        if (!Files.isRegularFile(path) || Files.isSymbolicLink(path)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_PATH_UNSAFE,
                    "Evidence index file is missing or a symbolic link: " + path));
        }
        return parse(Files.readAllBytes(path), limits, token);
    }

    public static EvidenceIndex fromMap(Map<?, ?> map) throws DiagnosticException {
        try {
            String schemaId = map.get("schemaId") instanceof String s ? s : SCHEMA_ID;
            String generatedAt = requireString(map, "generatedAt");
            String toolVersion = requireString(map, "toolVersion");
            String ghidraVersion = requireString(map, "ghidraVersion");

            List<EvidenceIndexEntry> entries = new ArrayList<>();
            if (map.get("entries") instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> entryMap) {
                        entries.add(EvidenceIndexEntry.fromMap(entryMap));
                    }
                }
            }

            return new EvidenceIndex(schemaId, generatedAt, toolVersion, ghidraVersion, entries);
        } catch (IllegalArgumentException exception) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.EVIDENCE_INDEX_INVALID,
                    "Invalid evidence index: " + exception.getMessage()));
        }
    }

    private static String requireString(Map<?, ?> map, String key) {
        Object val = map.get(key);
        if (val instanceof String s && !s.isBlank()) {
            return s;
        }
        throw new IllegalArgumentException("Missing or blank string field: " + key);
    }
}
