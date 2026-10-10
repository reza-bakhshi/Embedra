package io.github.rezabakhshi.embedra.core.fixture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FixtureManifestTest {

    private static final Path PROJECT_DIR = Path.of(System.getProperty("embedra.projectDir"));

    @Test
    void allCommittedFixtureManifestsAreValid() throws IOException, DiagnosticException {
        Path fixturesDir = PROJECT_DIR.resolve("src/test/resources/fixtures");
        assertTrue(Files.isDirectory(fixturesDir), "Fixtures directory must exist");

        ParserLimits limits = ParserLimits.defaults();
        CancellationToken token = CancellationToken.none();

        int count = 0;
        try (Stream<Path> stream = Files.walk(fixturesDir)) {
            List<Path> manifests = stream.filter(p -> p.toString().endsWith(".manifest.json")).toList();
            for (Path manifestPath : manifests) {
                FixtureManifest manifest = FixtureManifest.read(manifestPath, limits, token);
                assertNotNull(manifest.fixtureId());
                assertNotNull(manifest.sha256());
                assertEquals(64, manifest.sha256().length());
                assertNotNull(manifest.target());
                assertNotNull(manifest.inputFormat());
                assertNotNull(manifest.origin());
                assertNotNull(manifest.license());
                assertEquals(RedistributionStatus.REDISTRIBUTABLE, manifest.redistributionStatus());
                assertFalse(manifest.oracleCommands().isEmpty());
                assertFalse(manifest.requirements().isEmpty());

                // Find corresponding binary file
                String manifestFilename = manifestPath.getFileName().toString();
                int suffixLen = ".manifest.json".length();
                String binaryFilename = manifestFilename.substring(0, manifestFilename.length() - suffixLen);
                Path binaryPath = manifestPath.getParent().resolve(binaryFilename);
                assertTrue(Files.isRegularFile(binaryPath), "Binary must exist: " + binaryPath);
                manifest.validateFixtureBinary(binaryPath);
                count++;
            }
        }
        assertTrue(count > 0, "Must have validated at least one fixture manifest");
    }

    @Test
    void rejectsInvalidDigest() {
        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                FixtureManifest.SCHEMA_ID,
                "valid.fixture.id",
                "not-a-valid-sha256",
                "STM32F4",
                null,
                "ELF",
                "test",
                "Apache-2.0",
                RedistributionStatus.REDISTRIBUTABLE,
                null,
                "rev1",
                "make",
                "gcc",
                List.of("readelf"),
                "snapshots/test.json",
                List.of("T033"),
                null,
                null,
                null));
    }

    @Test
    void rejectsPathTraversalInFixtureId() {
        String validDigest = "a".repeat(64);
        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                FixtureManifest.SCHEMA_ID,
                "../escape/id",
                validDigest,
                "STM32F4",
                null,
                "ELF",
                "test",
                "Apache-2.0",
                RedistributionStatus.REDISTRIBUTABLE,
                null,
                "rev1",
                "make",
                "gcc",
                List.of("readelf"),
                "snapshots/test.json",
                List.of("T033"),
                null,
                null,
                null));
    }

    @Test
    void rejectsPathTraversalInExpectedSnapshot() {
        String validDigest = "a".repeat(64);
        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                FixtureManifest.SCHEMA_ID,
                "valid.fixture.id",
                validDigest,
                "STM32F4",
                null,
                "ELF",
                "test",
                "Apache-2.0",
                RedistributionStatus.REDISTRIBUTABLE,
                null,
                "rev1",
                "make",
                "gcc",
                List.of("readelf"),
                "../escape/snapshot.json",
                List.of("T033"),
                null,
                null,
                null));
    }

    @Test
    void validatesDigestIntegrityAgainstBinary(@TempDir Path tempDir) throws IOException, DiagnosticException {
        Path bin = tempDir.resolve("sample.bin");
        byte[] content = new byte[] {0x12, 0x34, 0x56, 0x78};
        Files.write(bin, content);
        String digest = FixtureManifest.computeSha256(content);

        FixtureManifest manifest = new FixtureManifest(
                FixtureManifest.SCHEMA_ID,
                "test.fixture.valid",
                digest,
                "STM32F4",
                null,
                "BIN",
                "unit-test",
                "Apache-2.0",
                RedistributionStatus.REDISTRIBUTABLE,
                null,
                "rev1",
                "cmd",
                "gcc",
                List.of("oracle"),
                "snapshots/out.json",
                List.of("T067"),
                null,
                null,
                null);

        manifest.validateFixtureBinary(bin);

        // Mutate binary to trigger mismatch
        Files.write(bin, new byte[] {0x00, 0x00});
        DiagnosticException ex = assertThrows(DiagnosticException.class, () -> manifest.validateFixtureBinary(bin));
        assertEquals(DiagnosticCode.FIXTURE_INTEGRITY_MISMATCH, ex.diagnostic().code());
    }

    @Test
    void serializesToJsonAndDeserializes() throws DiagnosticException {
        String digest = "b".repeat(64);
        FixtureManifest original = new FixtureManifest(
                FixtureManifest.SCHEMA_ID,
                "test.serialization.fixture",
                digest,
                "RP2040",
                "RP2040-B2",
                "UF2",
                "synthetic",
                "Apache-2.0",
                RedistributionStatus.REDISTRIBUTABLE,
                Map.of("repo", "embedra"),
                "git-commit",
                "python3 build.py",
                "arm-none-eabi-gcc",
                List.of("picotool info <fixture>"),
                "snapshots/rp2040.json",
                List.of("T050", "RP-001"),
                false,
                "rev-1",
                null);

        String json = original.toJson();
        assertNotNull(json);

        FixtureManifest parsed = FixtureManifest.parse(json, ParserLimits.defaults(), CancellationToken.none());
        assertEquals(original.fixtureId(), parsed.fixtureId());
        assertEquals(original.sha256(), parsed.sha256());
        assertEquals(original.target(), parsed.target());
        assertEquals(original.device(), parsed.device());
        assertEquals(original.inputFormat(), parsed.inputFormat());
        assertEquals(original.redistributionStatus(), parsed.redistributionStatus());
        assertEquals(original.requirements(), parsed.requirements());
    }

    @Test
    void exercisesRedistributionStatusMethods() {
        assertTrue(RedistributionStatus.REDISTRIBUTABLE.isRedistributable());
        assertFalse(RedistributionStatus.REDISTRIBUTABLE.isPrivate());

        assertFalse(RedistributionStatus.RESTRICTED_LOCAL.isRedistributable());
        assertTrue(RedistributionStatus.RESTRICTED_LOCAL.isPrivate());

        assertFalse(RedistributionStatus.PROPRIETARY_PRIVATE.isRedistributable());
        assertTrue(RedistributionStatus.PROPRIETARY_PRIVATE.isPrivate());

        assertEquals(RedistributionStatus.REDISTRIBUTABLE, RedistributionStatus.parse("REDISTRIBUTABLE"));
        assertEquals(RedistributionStatus.RESTRICTED_LOCAL, RedistributionStatus.parse("restricted_local"));
        assertEquals(RedistributionStatus.PROPRIETARY_PRIVATE, RedistributionStatus.parse("PROPRIETARY_PRIVATE"));

        assertThrows(IllegalArgumentException.class, () -> RedistributionStatus.parse(null));
        assertThrows(IllegalArgumentException.class, () -> RedistributionStatus.parse("INVALID_STATUS"));
    }

    @Test
    void exercisesAllFixtureManifestConstructorValidations() {
        String validDigest = "c".repeat(64);
        List<String> validOracles = List.of("oracle");
        List<String> validReqs = List.of("T001");

        assertThrows(NullPointerException.class, () -> new FixtureManifest(
                null, null, validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "   ", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "with\\backslash", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(NullPointerException.class, () -> new FixtureManifest(
                null, "id", null, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "   ", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "   ", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "   ", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "   ",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(NullPointerException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                null, null, "R", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "   ", "C", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "   ", "TC",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "   ",
                validOracles, "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                List.of(), "S", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "   ", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "/absolute/path", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "back\\slash", validReqs, null, null, null));

        assertThrows(IllegalArgumentException.class, () -> new FixtureManifest(
                null, "id", validDigest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                validOracles, "snapshot.json", List.of(), null, null, null));
    }

    @Test
    void exercisesFromMapAndValidationErrors(@TempDir Path tempDir) {
        // Non-map JSON in parse
        assertThrows(DiagnosticException.class, () ->
                FixtureManifest.parse("[1, 2]", ParserLimits.defaults(), CancellationToken.none()));

        // read non-existent path
        assertThrows(DiagnosticException.class, () ->
                FixtureManifest.read(tempDir.resolve("missing.json"),
                        ParserLimits.defaults(), CancellationToken.none()));

        // validateFixtureBinary non-existent file
        String digest = "d".repeat(64);
        FixtureManifest manifest = new FixtureManifest(
                FixtureManifest.SCHEMA_ID, "id", digest, "T", null, "F", "O", "L",
                RedistributionStatus.REDISTRIBUTABLE, null, "R", "C", "TC",
                List.of("O"), "S", List.of("REQ"), null, null, null);

        assertThrows(DiagnosticException.class, () ->
                manifest.validateFixtureBinary(tempDir.resolve("non-existent-binary")));

        // validateFixtureBinary directory
        assertThrows(DiagnosticException.class, () ->
                manifest.validateFixtureBinary(tempDir));

        // Invalid map in fromMap (missing fields, invalid lists)
        assertThrows(DiagnosticException.class, () -> FixtureManifest.fromMap(Map.of()));
        assertThrows(DiagnosticException.class, () -> FixtureManifest.fromMap(Map.of(
                "fixtureId", "id", "sha256", digest, "target", "T", "inputFormat", "F",
                "origin", "O", "license", "L", "redistributionStatus", "INVALID")));
        Map<String, Object> badListMap = new java.util.LinkedHashMap<>();
        badListMap.put("fixtureId", "id");
        badListMap.put("sha256", digest);
        badListMap.put("target", "T");
        badListMap.put("inputFormat", "F");
        badListMap.put("origin", "O");
        badListMap.put("license", "L");
        badListMap.put("redistributionStatus", "REDISTRIBUTABLE");
        badListMap.put("generatorRevision", "R");
        badListMap.put("generationCommand", "C");
        badListMap.put("toolchain", "TC");
        badListMap.put("oracleCommands", List.of(123));
        badListMap.put("expectedSnapshot", "S");
        badListMap.put("requirements", List.of("REQ"));
        assertThrows(DiagnosticException.class, () -> FixtureManifest.fromMap(badListMap));

        // parseStringList with a blank string inside the list
        Map<String, Object> blankItemMap = new java.util.LinkedHashMap<>(badListMap);
        blankItemMap.put("oracleCommands", List.of("   "));
        assertThrows(DiagnosticException.class, () -> FixtureManifest.fromMap(blankItemMap));

        // requireString with blank string
        Map<String, Object> blankTargetMap = new java.util.LinkedHashMap<>(badListMap);
        blankTargetMap.put("oracleCommands", List.of("cmd"));
        blankTargetMap.put("target", "   ");
        assertThrows(DiagnosticException.class, () -> FixtureManifest.fromMap(blankTargetMap));

        // Symlinks in read and validateFixtureBinary
        Path realFile = tempDir.resolve("real.json");
        try {
            Files.writeString(realFile, "{}");
            Path linkFile = tempDir.resolve("link.json");
            Files.createSymbolicLink(linkFile, realFile);
            assertThrows(DiagnosticException.class, () ->
                    FixtureManifest.read(linkFile, ParserLimits.defaults(), CancellationToken.none()));
            assertThrows(DiagnosticException.class, () ->
                    manifest.validateFixtureBinary(linkFile));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Full optional fields map
        Map<String, Object> fullMap = new java.util.LinkedHashMap<>();
        fullMap.put("schemaId", FixtureManifest.SCHEMA_ID);
        fullMap.put("fixtureId", "id");
        fullMap.put("sha256", digest);
        fullMap.put("target", "T");
        fullMap.put("device", "D");
        fullMap.put("inputFormat", "F");
        fullMap.put("origin", "O");
        fullMap.put("license", "L");
        fullMap.put("redistributionStatus", "REDISTRIBUTABLE");
        fullMap.put("generatorRevision", "R");
        fullMap.put("generationCommand", "C");
        fullMap.put("toolchain", "TC");
        fullMap.put("oracleCommands", List.of("cmd"));
        fullMap.put("expectedSnapshot", "S");
        fullMap.put("requirements", List.of("REQ"));
        fullMap.put("malformed", true);
        fullMap.put("scriptRevision", "SR");
        fullMap.put("privateDigestOnly", true);
        try {
            FixtureManifest fullManifest = FixtureManifest.fromMap(fullMap);
            assertEquals("D", fullManifest.device());
            assertTrue(fullManifest.malformed());
            assertTrue(fullManifest.privateDigestOnly());
            assertEquals("SR", fullManifest.scriptRevision());
            assertNotNull(fullManifest.toMap());
        } catch (DiagnosticException e) {
            throw new RuntimeException(e);
        }
    }
}
