package io.github.rezabakhshi.embedra.core.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class EvidenceIndexTest {

    private static final Path PROJECT_DIR = Path.of(System.getProperty("embedra.projectDir"));

    @Test
    void serializesAndDeserializesEvidenceIndex() throws DiagnosticException {
        EvidenceIndexEntry entry1 = new EvidenceIndexEntry(
                "AN-015",
                "T066",
                "CryptoCorpusBenchmarkTest#testBenchmark",
                "esp32s3.crypto.pos-01",
                EvidenceResultStatus.PASS,
                List.of(".embedra/evidence/tasks/T066.md", "dist/Embedra.zip"),
                "100% precision and recall");

        EvidenceIndexEntry entry2 = new EvidenceIndexEntry(
                "ESP-001",
                "T008",
                "Esp32S3GoldenFixtureTest#testLoad",
                "esp32s3.esptool-v5.4.0.esp32s3-freestanding-minimal",
                EvidenceResultStatus.PASS,
                List.of(".embedra/evidence/tasks/T008.md"),
                "Golden image verified");

        EvidenceIndex index = new EvidenceIndex(
                EvidenceIndex.SCHEMA_ID,
                "2026-10-10T20:00:00Z",
                "1.0.0",
                "12.1.3",
                List.of(entry2, entry1)); // out of order to test sorting

        assertEquals(2, index.entries().size());
        assertEquals("AN-015", index.entries().get(0).requirementId()); // sorted first

        String json = index.toJson();
        assertNotNull(json);

        EvidenceIndex parsed = EvidenceIndex.parse(
                json.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(index.schemaId(), parsed.schemaId());
        assertEquals(index.toolVersion(), parsed.toolVersion());
        assertEquals(index.ghidraVersion(), parsed.ghidraVersion());
        assertEquals(2, parsed.entries().size());

        List<EvidenceIndexEntry> an015 = parsed.findEntriesForRequirement("AN-015");
        assertEquals(1, an015.size());
        assertEquals("T066", an015.get(0).taskId());

        List<EvidenceIndexEntry> t066 = parsed.findEntriesForTask("T066");
        assertEquals(1, t066.size());

        Set<String> allReqs = parsed.allCoveredRequirements();
        assertTrue(allReqs.contains("AN-015"));
        assertTrue(allReqs.contains("ESP-001"));

        Set<String> allTasks = parsed.allCoveredTasks();
        assertTrue(allTasks.contains("T066"));
        assertTrue(allTasks.contains("T008"));
    }

    @Test
    void generatesEvidenceIndexFromRealProject() throws DiagnosticException, IOException {
        EvidenceIndexGenerator generator = new EvidenceIndexGenerator("1.0.0", "12.1.3");
        EvidenceIndex index = generator.generateFromProject(
                PROJECT_DIR,
                ParserLimits.defaults(),
                CancellationToken.none());

        assertNotNull(index);
        assertFalse(index.entries().isEmpty(), "Evidence index must contain entries");

        // Verify key requirements are covered
        Set<String> requirements = index.allCoveredRequirements();
        assertTrue(requirements.contains("T066"), "Must contain T066");
        assertTrue(requirements.contains("T008"), "Must contain T008");
        assertTrue(requirements.contains("ESP-001"), "Must contain ESP-001");
        assertTrue(requirements.contains("STM-001"), "Must contain STM-001");
        assertTrue(requirements.contains("RP-001"), "Must contain RP-001");

        // Verify key tasks are covered
        Set<String> tasks = index.allCoveredTasks();
        assertTrue(tasks.contains("T001"));
        assertTrue(tasks.contains("T065"));
        assertTrue(tasks.contains("T066"));

        // Generate canonical evidence index file to .embedra/evidence/evidence-index.json
        Path evidenceIndexFile = PROJECT_DIR.resolve(".embedra/evidence/evidence-index.json");
        Files.writeString(evidenceIndexFile, index.toJson());
        assertTrue(Files.isRegularFile(evidenceIndexFile));

        // Read it back and verify
        EvidenceIndex readBack = EvidenceIndex.read(
                evidenceIndexFile,
                ParserLimits.defaults(),
                CancellationToken.none());
        assertEquals(index.entries().size(), readBack.entries().size());
    }

    @Test
    void exercisesEvidenceResultStatusBranches() {
        assertEquals(EvidenceResultStatus.PASS, EvidenceResultStatus.parse("PASS"));
        assertEquals(EvidenceResultStatus.FAIL, EvidenceResultStatus.parse("fail"));
        assertEquals(EvidenceResultStatus.SKIPPED, EvidenceResultStatus.parse("skipped"));
        assertThrows(IllegalArgumentException.class, () -> EvidenceResultStatus.parse(null));
    }

    @Test
    void exercisesEvidenceIndexEntryValidationsAndFromMap() {
        assertThrows(NullPointerException.class, () ->
                new EvidenceIndexEntry(null, "T1", "test", null, EvidenceResultStatus.PASS, List.of(), null));
        assertThrows(IllegalArgumentException.class, () ->
                new EvidenceIndexEntry("  ", "T1", "test", null, EvidenceResultStatus.PASS, List.of(), null));
        assertThrows(NullPointerException.class, () ->
                new EvidenceIndexEntry("REQ", null, "test", null, EvidenceResultStatus.PASS, List.of(), null));
        assertThrows(IllegalArgumentException.class, () ->
                new EvidenceIndexEntry("REQ", "  ", "test", null, EvidenceResultStatus.PASS, List.of(), null));
        assertThrows(NullPointerException.class, () ->
                new EvidenceIndexEntry("REQ", "T1", null, null, EvidenceResultStatus.PASS, List.of(), null));
        assertThrows(IllegalArgumentException.class, () ->
                new EvidenceIndexEntry("REQ", "T1", "  ", null, EvidenceResultStatus.PASS, List.of(), null));
        assertThrows(NullPointerException.class, () ->
                new EvidenceIndexEntry("REQ", "T1", "test", null, null, List.of(), null));
        assertThrows(NullPointerException.class, () ->
                new EvidenceIndexEntry("REQ", "T1", "test", null, EvidenceResultStatus.PASS, null, null));

        // fromMap with missing fields
        assertThrows(IllegalArgumentException.class, () -> EvidenceIndexEntry.fromMap(java.util.Map.of()));

        // fromMap with retainedArtifacts containing non-strings
        java.util.Map<String, Object> map = java.util.Map.of(
                "requirementId", "REQ",
                "taskId", "T1",
                "testName", "test",
                "resultStatus", "PASS",
                "retainedArtifacts", List.of("valid", 123, "   "));
        EvidenceIndexEntry entry = EvidenceIndexEntry.fromMap(map);
        assertEquals(1, entry.retainedArtifacts().size());
        assertEquals("valid", entry.retainedArtifacts().get(0));
    }

    @Test
    void exercisesEvidenceIndexQueriesAndErrorHandling(@org.junit.jupiter.api.io.TempDir Path tempDir) {
        EvidenceIndexEntry entry = new EvidenceIndexEntry(
                "REQ", "T1", "test", "fix-1", EvidenceResultStatus.PASS, List.of(), null);
        EvidenceIndex index = new EvidenceIndex(
                EvidenceIndex.SCHEMA_ID, "2026-10-10", "1.0", "12.1.3", List.of(entry));

        // Null query arguments
        assertTrue(index.findEntriesForRequirement(null).isEmpty());
        assertTrue(index.findEntriesForTask(null).isEmpty());
        assertTrue(index.findEntriesForFixture(null).isEmpty());
        assertTrue(index.findEntriesForFixture("non-existent").isEmpty());

        // Invalid schema ID in constructor
        assertThrows(IllegalArgumentException.class, () ->
                new EvidenceIndex("urn:bad:schema", "2026-10-10", "1.0", "12.1.3", List.of()));

        // Parse non-map JSON
        assertThrows(DiagnosticException.class, () ->
                EvidenceIndex.parse("[1, 2]".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        ParserLimits.defaults(), CancellationToken.none()));

        // Read non-existent file
        assertThrows(DiagnosticException.class, () ->
                EvidenceIndex.read(tempDir.resolve("missing.json"), ParserLimits.defaults(), CancellationToken.none()));

        // Read symlink
        Path real = tempDir.resolve("real_index.json");
        try {
            Files.writeString(real, index.toJson());
            Path link = tempDir.resolve("link_index.json");
            Files.createSymbolicLink(link, real);
            assertThrows(DiagnosticException.class, () ->
                    EvidenceIndex.read(link, ParserLimits.defaults(), CancellationToken.none()));
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }

        // fromMap with default schemaId, non-list entries, list with non-map entries
        java.util.Map<String, Object> mapWithoutSchema = java.util.Map.of(
                "generatedAt", "now",
                "toolVersion", "1.0",
                "ghidraVersion", "12.1.3",
                "entries", List.of("not-a-map", 42));
        try {
            EvidenceIndex fromM = EvidenceIndex.fromMap(mapWithoutSchema);
            assertEquals(EvidenceIndex.SCHEMA_ID, fromM.schemaId());
            assertTrue(fromM.entries().isEmpty());
        } catch (DiagnosticException e) {
            throw new RuntimeException(e);
        }

        // toMap with blank/null fixtureId and notes
        EvidenceIndexEntry blankEntry = new EvidenceIndexEntry(
                "REQ", "T1", "test", "", EvidenceResultStatus.PASS, List.of(), "");
        java.util.Map<String, Object> blankMap = blankEntry.toMap();
        assertFalse(blankMap.containsKey("fixtureId"));
        assertFalse(blankMap.containsKey("notes"));
    }

    @Test
    void generatorRunsOnEmptyProject(@org.junit.jupiter.api.io.TempDir Path tempDir)
            throws DiagnosticException, java.io.IOException {
        EvidenceIndexGenerator generator = new EvidenceIndexGenerator("1.0", "12.1.3");
        EvidenceIndexEntry explicit = new EvidenceIndexEntry(
                "REQ_MANUAL", "T099", "ManualTest", null, EvidenceResultStatus.PASS, List.of(), "manual");
        generator.addEntry(explicit);

        EvidenceIndex index = generator.generateFromProject(tempDir, ParserLimits.defaults(), CancellationToken.none());
        assertNotNull(index);
        assertEquals(1, index.entries().size());
        assertEquals("REQ_MANUAL", index.entries().get(0).requirementId());
    }

    @Test
    void generatorHandlesNonTaskEvidenceAndManifestWithoutTask(@org.junit.jupiter.api.io.TempDir Path tempDir)
            throws DiagnosticException, java.io.IOException {
        Path tasksDir = tempDir.resolve(".embedra/evidence/tasks");
        Files.createDirectories(tasksDir);
        // Markdown file without Txxx in name
        Files.writeString(tasksDir.resolve("general-notes.md"), "# Notes");

        Path fixturesDir = tempDir.resolve("src/test/resources/fixtures");
        Files.createDirectories(fixturesDir);

        String digest = "f".repeat(64);
        io.github.rezabakhshi.embedra.core.fixture.FixtureManifest manifest =
                new io.github.rezabakhshi.embedra.core.fixture.FixtureManifest(
                        io.github.rezabakhshi.embedra.core.fixture.FixtureManifest.SCHEMA_ID,
                        "custom.fixture", digest, "target", null, "format", "origin", "license",
                        io.github.rezabakhshi.embedra.core.fixture.RedistributionStatus.REDISTRIBUTABLE,
                        null, "rev", "cmd", "tool", List.of("oracle"), "snapshot.json",
                        List.of("CUSTOM_SPEC_REQ"), null, null, null);

        Files.writeString(fixturesDir.resolve("custom.bin.manifest.json"), manifest.toJson());

        EvidenceIndexGenerator generator = new EvidenceIndexGenerator("1.0", "12.1.3");
        EvidenceIndex index = generator.generateFromProject(
                tempDir, ParserLimits.defaults(), CancellationToken.none());
        assertNotNull(index);
        assertFalse(index.entries().isEmpty());
        // Custom spec req was bound to default task T067 and had no task evidence
        assertEquals("CUSTOM_SPEC_REQ", index.entries().get(0).requirementId());
        assertEquals("T067", index.entries().get(0).taskId());
        assertEquals(1, index.entries().get(0).retainedArtifacts().size());
    }
}
