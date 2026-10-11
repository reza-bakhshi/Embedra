package io.github.rezabakhshi.embedra.core.budget;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Validates file and directory paths against path traversal, Zip Slip,
 * symlink escapes, and null-byte injection (AN-009, Section 5.3).
 */
public final class AdversarialPathGuard {

    private AdversarialPathGuard() {
    }

    /**
     * Asserts that a relative path does not escape its root or contain unsafe path elements.
     *
     * @param relativePath candidate relative path string
     * @throws DiagnosticException if the path contains traversal sequences or unsafe tokens
     */
    public static void validateRelativePathSafety(String relativePath) throws DiagnosticException {
        Objects.requireNonNull(relativePath, "relativePath must not be null");

        if (relativePath.isBlank()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PATH_TRAVERSAL_DETECTED,
                    "Relative path must not be blank"));
        }

        if (relativePath.contains("\0")) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PATH_TRAVERSAL_DETECTED,
                    "Path contains null byte injection: " + relativePath));
        }

        // Check for Windows or Unix absolute roots
        if (relativePath.startsWith("/") || relativePath.startsWith("\\")) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PATH_TRAVERSAL_DETECTED,
                    "Path must not start with an absolute root slash: " + relativePath));
        }

        if (relativePath.length() >= 2 && Character.isLetter(relativePath.charAt(0))
                && relativePath.charAt(1) == ':') {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PATH_TRAVERSAL_DETECTED,
                    "Path must not start with a drive letter: " + relativePath));
        }

        // Normalize separators to forward slash
        String normalized = relativePath.replace('\\', '/');

        // Check path tokens
        String[] parts = normalized.split("/+");
        for (String part : parts) {
            if ("..".equals(part)) {
                throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PATH_TRAVERSAL_DETECTED,
                    "Path contains parent directory traversal '..': " + relativePath));
            }
        }
    }

    /**
     * Resolves a relative path against a base directory and verifies it does not escape.
     */
    public static Path resolveSafely(Path basePath, String relativePath) throws DiagnosticException {
        Objects.requireNonNull(basePath, "basePath must not be null");
        validateRelativePathSafety(relativePath);

        Path normalizedBase = basePath.toAbsolutePath().normalize();
        Path resolved = normalizedBase.resolve(relativePath).normalize();

        // Check for symlink escaping outside basePath if target exists
        if (Files.exists(resolved) && Files.isSymbolicLink(resolved)) {
            try {
                Path realTarget = resolved.toRealPath();
                if (!realTarget.startsWith(normalizedBase)) {
                    throw new DiagnosticException(Diagnostic.error(
                            DiagnosticCode.PATH_TRAVERSAL_DETECTED,
                            String.format("Symlink target '%s' escapes base directory '%s'",
                                    realTarget, normalizedBase)));
                }
            } catch (IOException e) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PATH_TRAVERSAL_DETECTED,
                        "Failed to resolve real path for symlink: " + e.getMessage()));
            }
        }

        return resolved;
    }
}
