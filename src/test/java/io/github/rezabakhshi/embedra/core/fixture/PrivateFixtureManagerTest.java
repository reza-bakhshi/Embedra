package io.github.rezabakhshi.embedra.core.fixture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PrivateFixtureManagerTest {

    private static final Path PROJECT_DIR = Path.of(System.getProperty("embedra.projectDir"));

    @Test
    void defaultRegistryContainsT021FlashDumpDescriptor() {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        Optional<PrivateFixtureManager.PrivateFixtureDescriptor> desc =
                manager.getDescriptor(PrivateFixtureManager.T021_DUMP_FIXTURE_ID);

        assertTrue(desc.isPresent());
        assertEquals("ESP32-S3", desc.get().target());
        assertEquals(PrivateFixtureManager.T021_DUMP_SHA256, desc.get().expectedSha256());
        assertEquals(RedistributionStatus.RESTRICTED_LOCAL, desc.get().redistributionStatus());
    }

    @Test
    void missingLocalFileReturnsEmptyWithoutFailingCI(@TempDir Path emptyProject)
            throws IOException, DiagnosticException {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        Optional<Path> resolved = manager.resolvePrivateFixture(
                PrivateFixtureManager.T021_DUMP_FIXTURE_ID, emptyProject);
        assertTrue(resolved.isEmpty(), "Missing local private fixture must return empty Optional for CI");
    }

    @Test
    void handlesBlankOrNonExistentSystemPropertyAndNullRoot() throws IOException, DiagnosticException {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        String originalProp = System.getProperty("embedra.private.fixtures.dir");
        try {
            System.setProperty("embedra.private.fixtures.dir", "   ");
            Optional<Path> resolvedBlank = manager.resolvePrivateFixture(
                    PrivateFixtureManager.T021_DUMP_FIXTURE_ID, null);
            assertTrue(resolvedBlank.isEmpty());

            System.setProperty("embedra.private.fixtures.dir", "/path/that/does/not/exist");
            Optional<Path> resolvedNonExistent = manager.resolvePrivateFixture(
                    PrivateFixtureManager.T021_DUMP_FIXTURE_ID, null);
            assertTrue(resolvedNonExistent.isEmpty());

            System.clearProperty("embedra.private.fixtures.dir");
            Optional<Path> resolvedNullRoot = manager.resolvePrivateFixture(
                    PrivateFixtureManager.T021_DUMP_FIXTURE_ID, null);
            assertTrue(resolvedNullRoot.isEmpty());
        } finally {
            if (originalProp != null) {
                System.setProperty("embedra.private.fixtures.dir", originalProp);
            } else {
                System.clearProperty("embedra.private.fixtures.dir");
            }
        }
    }

    @Test
    void resolvesExistingPrivateFixtureAndVerifiesDigest(@TempDir Path tempDir)
            throws IOException, DiagnosticException {
        PrivateFixtureManager manager = new PrivateFixtureManager();

        byte[] fakeCapture = new byte[] {0x45, 0x4d, 0x42, 0x52, 0x41};
        String expectedSha256 = FixtureManifest.computeSha256(fakeCapture);

        String fixtureId = "custom.private.test-fixture";
        manager.register(new PrivateFixtureManager.PrivateFixtureDescriptor(
                fixtureId,
                expectedSha256,
                "ESP32-S3",
                "private/dump.bin",
                "Test private capture",
                RedistributionStatus.PROPRIETARY_PRIVATE));

        Path privateFile = tempDir.resolve("private/dump.bin");
        Files.createDirectories(privateFile.getParent());
        Files.write(privateFile, fakeCapture);

        Optional<Path> resolved = manager.resolvePrivateFixture(fixtureId, tempDir);
        assertTrue(resolved.isPresent());
        assertEquals(privateFile.toAbsolutePath().normalize(), resolved.get().toAbsolutePath().normalize());

        // Mutate binary to corrupt digest
        Files.write(privateFile, new byte[] {0x00, 0x00});
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                manager.resolvePrivateFixture(fixtureId, tempDir));
        assertEquals(DiagnosticCode.FIXTURE_INTEGRITY_MISMATCH, ex.diagnostic().code());
    }

    @Test
    void rejectsPrivateFixturePlacedInPublicFixtureTree(@TempDir Path tempDir) throws IOException {
        PrivateFixtureManager manager = new PrivateFixtureManager();

        byte[] fakeCapture = new byte[] {0x01, 0x02};
        String sha = FixtureManifest.computeSha256(fakeCapture);

        String fixtureId = "leaked.private.fixture";
        manager.register(new PrivateFixtureManager.PrivateFixtureDescriptor(
                fixtureId,
                sha,
                "STM32F4",
                "src/test/resources/fixtures/leaked.bin",
                "Leaked fixture in public tree",
                RedistributionStatus.RESTRICTED_LOCAL));

        Path leakedFile = tempDir.resolve("src/test/resources/fixtures/leaked.bin");
        Files.createDirectories(leakedFile.getParent());
        Files.write(leakedFile, fakeCapture);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                manager.resolvePrivateFixture(fixtureId, tempDir));
        assertEquals(DiagnosticCode.FIXTURE_REDISTRIBUTION_INVALID, ex.diagnostic().code());
        assertTrue(ex.diagnostic().message().contains("public redistributable fixture directory"));
    }

    @Test
    void rejectsSymbolicLinkPrivateFixture(@TempDir Path tempDir) throws IOException {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        Path target = tempDir.resolve("target.bin");
        Files.write(target, new byte[] {0x01});
        Path link = tempDir.resolve("link.bin");
        Files.createSymbolicLink(link, target);

        String fixtureId = "symlink.fixture";
        manager.register(new PrivateFixtureManager.PrivateFixtureDescriptor(
                fixtureId, "sha", "target", "link.bin", "desc",
                RedistributionStatus.RESTRICTED_LOCAL));

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                manager.resolvePrivateFixture(fixtureId, tempDir));
        assertEquals(DiagnosticCode.FIXTURE_PATH_UNSAFE, ex.diagnostic().code());
    }

    @Test
    void auditsRealRepositoryPublicFixtureTree() throws IOException, DiagnosticException {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        Path publicTree = PROJECT_DIR.resolve("src/test/resources/fixtures");
        // Must succeed with zero non-redistributable fixtures
        manager.auditPublicFixtureTree(publicTree);
        // Non-directory does not fail
        manager.auditPublicFixtureTree(PROJECT_DIR.resolve("non-existent-tree"));
    }

    @Test
    void rejectsRedistributableDescriptorCreation() {
        assertThrows(IllegalArgumentException.class, () ->
                new PrivateFixtureManager.PrivateFixtureDescriptor(
                        "id", "sha", "target", "path", "desc",
                        RedistributionStatus.REDISTRIBUTABLE));
    }

    @Test
    void unknownFixtureIdThrowsDiagnosticException(@TempDir Path tempDir) {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                manager.resolvePrivateFixture("non.existent.id", tempDir));
        assertEquals(DiagnosticCode.FIXTURE_MANIFEST_INVALID, ex.diagnostic().code());
    }

    @Test
    void resolvesViaSystemProperty(@TempDir Path tempDir) throws IOException, DiagnosticException {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        byte[] fakeData = new byte[] {0x11, 0x22};
        String sha = FixtureManifest.computeSha256(fakeData);

        String fixtureId = "sysprop.fixture";
        manager.register(new PrivateFixtureManager.PrivateFixtureDescriptor(
                fixtureId, sha, "ESP32", "custom/file.bin", "desc",
                RedistributionStatus.RESTRICTED_LOCAL));

        Path customDir = tempDir.resolve("custom_sysprop_dir");
        Files.createDirectories(customDir);
        Path bin = customDir.resolve("file.bin");
        Files.write(bin, fakeData);

        String originalProp = System.getProperty("embedra.private.fixtures.dir");
        try {
            System.setProperty("embedra.private.fixtures.dir", customDir.toString());
            Optional<Path> resolved = manager.resolvePrivateFixture(fixtureId, null);
            assertTrue(resolved.isPresent());
            assertEquals(bin.toAbsolutePath().normalize(), resolved.get().toAbsolutePath().normalize());
        } finally {
            if (originalProp != null) {
                System.setProperty("embedra.private.fixtures.dir", originalProp);
            } else {
                System.clearProperty("embedra.private.fixtures.dir");
            }
        }
    }

    @Test
    void rejectsCandidateWhenItIsADirectory(@TempDir Path tempDir) {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        String fixtureId = "dir.fixture";
        manager.register(new PrivateFixtureManager.PrivateFixtureDescriptor(
                fixtureId, "sha", "ESP32", "my_dir", "desc",
                RedistributionStatus.RESTRICTED_LOCAL));

        Path dir = tempDir.resolve("my_dir");
        try {
            Files.createDirectories(dir);
            DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                    manager.resolvePrivateFixture(fixtureId, tempDir));
            assertEquals(DiagnosticCode.FIXTURE_PATH_UNSAFE, ex.diagnostic().code());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void auditPublicFixtureTreeCatchesNonRedistributableManifest(@TempDir Path tempDir) throws IOException {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        Path publicDir = tempDir.resolve("fixtures");
        Files.createDirectories(publicDir);

        String digest = "e".repeat(64);
        FixtureManifest privateManifest = new FixtureManifest(
                FixtureManifest.SCHEMA_ID, "private.id", digest, "T", null, "F", "O", "L",
                RedistributionStatus.PROPRIETARY_PRIVATE, null, "R", "C", "TC",
                List.of("O"), "snapshot.json", List.of("REQ"), null, null, null);

        Files.writeString(publicDir.resolve("private.bin.manifest.json"), privateManifest.toJson());
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                manager.auditPublicFixtureTree(publicDir));
        assertEquals(DiagnosticCode.FIXTURE_REDISTRIBUTION_INVALID, ex.diagnostic().code());
    }

    @Test
    void allDescriptorsReturnsImmutableMap() {
        PrivateFixtureManager manager = new PrivateFixtureManager();
        assertFalse(manager.allDescriptors().isEmpty());
    }
}
