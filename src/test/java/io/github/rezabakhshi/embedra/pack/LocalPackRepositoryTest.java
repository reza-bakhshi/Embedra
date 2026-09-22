package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LocalPackRepositoryTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void installsWithoutChangingSourceAndSelectsHighestCompatibleVersion()
            throws IOException, DiagnosticException {
        Path sources = Files.createDirectory(temporaryDirectory.resolve("sources"));
        Path firstSource = PackTestFixtures.createPack(sources, "first",
            "vendor.synthetic", "1.0.0", "device-a");
        Path secondSource = PackTestFixtures.createPack(sources, "second",
            "vendor.synthetic", "1.2.0", "device-a");
        Path thirdSource = PackTestFixtures.createPack(sources, "third",
            "vendor.synthetic", "1.10.0", "device-a");
        LocalPackRepository repository = repository();

        InstalledPack first = repository.install(firstSource, CancellationToken.none());
        repository.install(secondSource, CancellationToken.none());
        repository.install(thirdSource, CancellationToken.none());

        assertEquals(PackVersion.parse("1.0.0"), first.manifest().version());
        assertTrue(Files.exists(first.directory().resolve("data/payload.bin")));
        assertTrue(Files.exists(firstSource.resolve("data/payload.bin")));
        InstalledPack selected = repository.select(
            new PackRequirement("vendor.synthetic", Optional.empty(), Optional.of("device-a")),
            CancellationToken.none());
        assertEquals(PackVersion.parse("1.10.0"), selected.manifest().version());
        InstalledPack exact = repository.select(new PackRequirement("vendor.synthetic",
            Optional.of(PackVersion.parse("1.0.0")), Optional.of("device-a")),
            CancellationToken.none());
        assertEquals(PackVersion.parse("1.0.0"), exact.manifest().version());
    }

    @Test
    void rejectsConflictsAndLeavesNoPartialInstallOnIntegrityFailure() throws IOException {
        Path good = PackTestFixtures.createPack(temporaryDirectory, "good",
            "vendor.synthetic", "1.0.0", "device-a");
        LocalPackRepository repository = repository();
        assertInstallSucceeds(repository, good);
        assertInstallCode(repository, good, DiagnosticCode.PACK_INSTALL_CONFLICT);

        Path bad = PackTestFixtures.createPack(temporaryDirectory, "bad",
            "vendor.bad", "1.0.0", "device-a");
        Files.writeString(bad.resolve("data/payload.bin"), "tampered", StandardCharsets.UTF_8);
        assertInstallCode(repository, bad, DiagnosticCode.PACK_INTEGRITY_MISMATCH);
        assertFalse(Files.exists(repository.root().resolve("vendor.bad/1.0.0")));
        try (var children = Files.list(repository.root())) {
            assertFalse(children.anyMatch(path -> path.getFileName().toString().startsWith(".install-")));
        }
    }

    @Test
    void reportsMissingAndIncompatibleOfflineSelections() throws IOException {
        LocalPackRepository repository = repository();
        assertSelectCode(repository, new PackRequirement("missing.pack", Optional.empty(),
            Optional.empty()), DiagnosticCode.PACK_NOT_FOUND);

        Path source = PackTestFixtures.createPack(temporaryDirectory, "device-pack",
            "vendor.synthetic", "1.0.0", "device-a");
        assertInstallSucceeds(repository, source);
        assertSelectCode(repository, new PackRequirement("vendor.synthetic", Optional.empty(),
            Optional.of("device-b")), DiagnosticCode.PACK_INCOMPATIBLE);
        assertSelectCode(repository, new PackRequirement("vendor.synthetic",
            Optional.of(PackVersion.parse("2.0.0")), Optional.empty()),
            DiagnosticCode.PACK_INCOMPATIBLE);
    }

    @Test
    void cancellationAndInstalledCorruptionFailWithoutNetworkFallback() throws IOException {
        Path source = PackTestFixtures.createPack(temporaryDirectory, "source",
            "vendor.synthetic", "1.0.0", "device-a");
        LocalPackRepository repository = repository();
        assertInstallCode(repository, source, DiagnosticCode.CANCELLED, () -> true);
        assertFalse(Files.exists(repository.root().resolve("vendor.synthetic/1.0.0")));

        InstalledPack installed;
        try {
            installed = repository.install(source, CancellationToken.none());
        }
        catch (DiagnosticException exception) {
            throw new AssertionError(exception);
        }
        Files.writeString(installed.directory().resolve("data/payload.bin"), "tampered",
            StandardCharsets.UTF_8);
        assertSelectCode(repository, new PackRequirement("vendor.synthetic", Optional.empty(),
            Optional.empty()), DiagnosticCode.PACK_INTEGRITY_MISMATCH);
    }

    private LocalPackRepository repository() throws IOException {
        return new LocalPackRepository(Files.createDirectory(temporaryDirectory.resolve("installed")),
            ParserLimits.defaults());
    }

    private static void assertInstallSucceeds(LocalPackRepository repository, Path source) {
        try {
            repository.install(source, CancellationToken.none());
        }
        catch (DiagnosticException exception) {
            throw new AssertionError(exception);
        }
    }

    private static void assertInstallCode(
            LocalPackRepository repository, Path source, DiagnosticCode expected) {
        assertInstallCode(repository, source, expected, CancellationToken.none());
    }

    private static void assertInstallCode(LocalPackRepository repository, Path source,
            DiagnosticCode expected, CancellationToken token) {
        DiagnosticException exception = assertThrows(DiagnosticException.class,
            () -> repository.install(source, token));
        assertEquals(expected, exception.diagnostic().code());
    }

    private static void assertSelectCode(
            LocalPackRepository repository, PackRequirement requirement, DiagnosticCode expected) {
        DiagnosticException exception = assertThrows(DiagnosticException.class,
            () -> repository.select(requirement, CancellationToken.none()));
        assertEquals(expected, exception.diagnostic().code());
    }
}
