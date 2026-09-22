package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/** Streaming integrity and path-safety verification for untrusted pack directories. */
public final class PackIntegrity {
    private static final int BUFFER_SIZE = 8192;

    private PackIntegrity() {
    }

    public static String contentDigest(List<PackFile> files) {
        MessageDigest digest = sha256Digest();
        files.stream().sorted(Comparator.comparing(PackFile::path)).forEach(file -> {
            String descriptor = file.path() + '\0' + file.size() + '\0' + file.sha256() + '\n';
            digest.update(descriptor.getBytes(StandardCharsets.UTF_8));
        });
        return HexFormat.of().formatHex(digest.digest());
    }

    public static void verify(
            Path packDirectory,
            PackManifest manifest,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Path root = packDirectory.toAbsolutePath().normalize();
        token.throwIfCancellationRequested();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(root)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_PATH_UNSAFE,
                "Pack root must be a real directory");
        }
        Set<String> expected = new HashSet<>();
        expected.add("pack.json");
        manifest.files().forEach(file -> expected.add(file.path()));
        Set<String> actual = inspectTree(root, limits, token);
        if (!actual.equals(expected)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
                "Pack contents differ from the manifest");
        }
        long total = 0;
        for (PackFile file : manifest.files()) {
            token.throwIfCancellationRequested();
            try {
                total = Math.addExact(total, file.size());
            }
            catch (ArithmeticException exception) {
                throw PackDiagnostics.failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "Pack content size overflows the configured accounting range");
            }
            if (file.size() > limits.maxInputBytes() || total > limits.maxExtractedBytes()) {
                throw PackDiagnostics.failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "Pack content exceeds the configured size limit");
            }
            verifyFile(root, file, token);
        }
        if (!manifest.contentDigest().equals(contentDigest(manifest.files()))) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
                "Pack aggregate content digest does not match");
        }
    }

    private static Set<String> inspectTree(
            Path root, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        HashSet<String> files = new HashSet<>();
        long objects = 0;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.toList()) {
                token.throwIfCancellationRequested();
                objects++;
                if (objects > limits.maxObjects()) {
                    throw PackDiagnostics.failure(DiagnosticCode.LIMIT_EXCEEDED,
                        "Pack tree exceeds the configured object limit");
                }
                if (Files.isSymbolicLink(path)) {
                    throw PackDiagnostics.failure(DiagnosticCode.PACK_PATH_UNSAFE,
                        "Pack tree contains a symbolic link");
                }
                if (!path.equals(root) && !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                        throw PackDiagnostics.failure(DiagnosticCode.PACK_PATH_UNSAFE,
                            "Pack tree contains a non-regular file");
                    }
                    String relative = root.relativize(path).toString().replace('\\', '/');
                    files.add(relative);
                }
            }
        }
        catch (IOException exception) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
                "Pack tree could not be inspected");
        }
        return files;
    }

    private static void verifyFile(Path root, PackFile file, CancellationToken token)
            throws DiagnosticException {
        Path path = root.resolve(file.path()).normalize();
        if (!path.startsWith(root) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
            || Files.isSymbolicLink(path)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_PATH_UNSAFE,
                "Pack file does not resolve to a safe regular file");
        }
        MessageDigest digest = sha256Digest();
        long length = 0;
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            int count;
            while ((count = input.read(buffer)) >= 0) {
                token.throwIfCancellationRequested();
                length = Math.addExact(length, count);
                if (length > file.size()) {
                    throw PackDiagnostics.failure(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
                        "Pack file length does not match the manifest");
                }
                digest.update(buffer, 0, count);
            }
        }
        catch (ArithmeticException | IOException exception) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
                "Pack file could not be verified");
        }
        String actualDigest = HexFormat.of().formatHex(digest.digest());
        if (length != file.size() || !actualDigest.equals(file.sha256())) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
                "Pack file digest or length does not match the manifest");
        }
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Required SHA-256 implementation is unavailable", exception);
        }
    }
}
