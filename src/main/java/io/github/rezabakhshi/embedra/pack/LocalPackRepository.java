package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Verified local installation and deterministic selection with no network access. */
public final class LocalPackRepository {
    private final Path root;

    private final ParserLimits limits;

    public LocalPackRepository(Path root, ParserLimits limits) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.limits = Objects.requireNonNull(limits, "limits");
        if (!Files.isDirectory(this.root, LinkOption.NOFOLLOW_LINKS)
            || Files.isSymbolicLink(this.root)) {
            throw new IllegalArgumentException("Pack repository root must be a real directory");
        }
    }

    public Path root() {
        return root;
    }

    public InstalledPack install(Path source, CancellationToken token) throws DiagnosticException {
        Path sourceRoot = Objects.requireNonNull(source, "source").toAbsolutePath().normalize();
        token.throwIfCancellationRequested();
        PackManifest manifest = PackManifest.read(sourceRoot.resolve("pack.json"), limits, token);
        PackIntegrity.verify(sourceRoot, manifest, limits, token);
        Path packParent = root.resolve(manifest.packId());
        Path destination = packParent.resolve(manifest.version().toString());
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INSTALL_CONFLICT,
                "The exact pack version is already installed");
        }
        Path temporary = null;
        try {
            Files.createDirectories(packParent);
            if (Files.isSymbolicLink(packParent)) {
                throw PackDiagnostics.failure(DiagnosticCode.PACK_PATH_UNSAFE,
                    "Pack repository identity directory is a symbolic link");
            }
            temporary = Files.createTempDirectory(root, ".install-");
            copyVerifiedPack(sourceRoot, temporary, manifest, token);
            PackManifest copied = PackManifest.read(temporary.resolve("pack.json"), limits, token);
            PackIntegrity.verify(temporary, copied, limits, token);
            try {
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
            }
            catch (AtomicMoveNotSupportedException exception) {
                throw PackDiagnostics.failure(DiagnosticCode.PACK_INSTALL_FAILED,
                    "Pack repository does not support atomic installation");
            }
            temporary = null;
            return new InstalledPack(copied, destination);
        }
        catch (IOException exception) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INSTALL_FAILED,
                "Pack installation failed before publication");
        }
        finally {
            if (temporary != null) {
                deleteTemporary(temporary);
            }
        }
    }

    public InstalledPack select(PackRequirement requirement, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(requirement, "requirement");
        token.throwIfCancellationRequested();
        Path identityRoot = root.resolve(requirement.packId());
        if (!Files.isDirectory(identityRoot, LinkOption.NOFOLLOW_LINKS)
            || Files.isSymbolicLink(identityRoot)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_NOT_FOUND,
                "No installed pack has the requested identity");
        }
        List<InstalledPack> installed = loadIdentity(identityRoot, requirement.packId(), token);
        if (installed.isEmpty()) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_NOT_FOUND,
                "No installed pack has the requested identity");
        }
        return installed.stream()
            .filter(pack -> requirement.exactVersion().isEmpty()
                || requirement.exactVersion().get().equals(pack.manifest().version()))
            .filter(pack -> requirement.deviceId().isEmpty()
                || pack.manifest().supportedDevices().contains(requirement.deviceId().get()))
            .max(Comparator.comparing(pack -> pack.manifest().version()))
            .orElseThrow(() -> PackDiagnostics.failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "Installed pack versions do not satisfy the offline selection constraints"));
    }

    private List<InstalledPack> loadIdentity(
            Path identityRoot, String expectedPackId, CancellationToken token)
            throws DiagnosticException {
        ArrayList<InstalledPack> result = new ArrayList<>();
        try (var children = Files.list(identityRoot)) {
            for (Path versionDirectory : children.sorted().toList()) {
                token.throwIfCancellationRequested();
                if (!Files.isDirectory(versionDirectory, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(versionDirectory)) {
                    throw PackDiagnostics.failure(DiagnosticCode.PACK_PATH_UNSAFE,
                        "Installed pack repository contains an unsafe entry");
                }
                PackManifest manifest = PackManifest.read(versionDirectory.resolve("pack.json"),
                    limits, token);
                if (!manifest.packId().equals(expectedPackId)
                    || !versionDirectory.getFileName().toString().equals(manifest.version().toString())) {
                    throw PackDiagnostics.failure(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
                        "Installed pack location does not match its manifest identity");
                }
                PackIntegrity.verify(versionDirectory, manifest, limits, token);
                result.add(new InstalledPack(manifest, versionDirectory));
            }
        }
        catch (IOException exception) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INSTALL_FAILED,
                "Installed pack repository could not be read");
        }
        return result;
    }

    private static void copyVerifiedPack(
            Path source, Path destination, PackManifest manifest, CancellationToken token)
            throws IOException, DiagnosticException {
        Files.copy(source.resolve("pack.json"), destination.resolve("pack.json"));
        for (PackFile file : manifest.files()) {
            token.throwIfCancellationRequested();
            Path target = destination.resolve(file.path());
            Files.createDirectories(target.getParent());
            Files.copy(source.resolve(file.path()), target);
        }
    }

    private static void deleteTemporary(Path temporary) {
        try (var paths = Files.walk(temporary)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
        catch (IOException ignored) {
            // The unreferenced temporary path is never treated as an installed pack.
        }
    }
}
