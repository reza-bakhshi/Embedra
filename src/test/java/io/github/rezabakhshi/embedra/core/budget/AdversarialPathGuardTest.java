package io.github.rezabakhshi.embedra.core.budget;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AdversarialPathGuardTest {

    @Test
    void validatesValidRelativePaths() {
        assertDoesNotThrow(() -> AdversarialPathGuard.validateRelativePathSafety("firmware.bin"));
        assertDoesNotThrow(() -> AdversarialPathGuard.validateRelativePathSafety("sections/code/flash.bin"));
        assertDoesNotThrow(() -> AdversarialPathGuard.validateRelativePathSafety("a/b/c/d.txt"));
        assertDoesNotThrow(() -> AdversarialPathGuard.validateRelativePathSafety("a\\b\\c.txt"));
    }

    @Test
    void rejectsNullAndBlankPaths() {
        assertThrows(NullPointerException.class, () -> AdversarialPathGuard.validateRelativePathSafety(null));

        DiagnosticException blankEx = assertThrows(DiagnosticException.class, () ->
                AdversarialPathGuard.validateRelativePathSafety("   "));
        assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, blankEx.diagnostic().code());
        assertTrue(blankEx.getMessage().contains("must not be blank"));
    }

    @Test
    void rejectsNullByteInjections() {
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialPathGuard.validateRelativePathSafety("safe/path\0evil.exe"));
        assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("null byte injection"));
    }

    @Test
    void rejectsAbsoluteRoots() {
        DiagnosticException unixEx = assertThrows(DiagnosticException.class, () ->
                AdversarialPathGuard.validateRelativePathSafety("/etc/passwd"));
        assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, unixEx.diagnostic().code());
        assertTrue(unixEx.getMessage().contains("absolute root slash"));

        DiagnosticException winEx = assertThrows(DiagnosticException.class, () ->
                AdversarialPathGuard.validateRelativePathSafety("\\windows\\system32"));
        assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, winEx.diagnostic().code());
        assertTrue(winEx.getMessage().contains("absolute root slash"));
    }

    @Test
    void rejectsWindowsDriveLetters() {
        DiagnosticException driveEx1 = assertThrows(DiagnosticException.class, () ->
                AdversarialPathGuard.validateRelativePathSafety("C:\\malware.bin"));
        assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, driveEx1.diagnostic().code());
        assertTrue(driveEx1.getMessage().contains("drive letter"));

        DiagnosticException driveEx2 = assertThrows(DiagnosticException.class, () ->
                AdversarialPathGuard.validateRelativePathSafety("D:foo.bin"));
        assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, driveEx2.diagnostic().code());
    }

    @Test
    void rejectsParentTraversalSequences() {
        String[] attacks = {
                "../escape.bin",
                "a/../../escape.bin",
                "foo/bar/../baz",
                "..\\windows\\system32",
                "a\\b\\..\\c"
        };

        for (String attack : attacks) {
            DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                    AdversarialPathGuard.validateRelativePathSafety(attack));
            assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, ex.diagnostic().code(), "Should reject: " + attack);
            assertTrue(ex.getMessage().contains("parent directory traversal"));
        }
    }

    @Test
    void resolvesSafelyWithinBaseDirectory(@TempDir Path tempDir) throws Exception {
        Path resolved = AdversarialPathGuard.resolveSafely(tempDir, "sub/dir/file.bin");
        assertNotNull(resolved);
        assertTrue(resolved.startsWith(tempDir.toAbsolutePath().normalize()));
    }

    @Test
    void resolveSafelyRejectsNullBaseOrRelative(@TempDir Path tempDir) {
        assertThrows(NullPointerException.class, () -> AdversarialPathGuard.resolveSafely(null, "sub/file"));
        assertThrows(NullPointerException.class, () -> AdversarialPathGuard.resolveSafely(tempDir, null));
    }

    @Test
    void resolvesExistingRegularFileSafely(@TempDir Path tempDir) throws Exception {
        Path existing = Files.createFile(tempDir.resolve("regular.bin"));
        Path resolved = AdversarialPathGuard.resolveSafely(tempDir, "regular.bin");
        assertEquals(existing.toAbsolutePath().normalize(), resolved);
    }

    @Test
    void validatesVariousRelativePathPrefixes() {
        assertDoesNotThrow(() -> AdversarialPathGuard.validateRelativePathSafety("x"));
        assertDoesNotThrow(() -> AdversarialPathGuard.validateRelativePathSafety("01/test.bin"));
        assertDoesNotThrow(() -> AdversarialPathGuard.validateRelativePathSafety("ab/test.bin"));
    }

    @Test
    void resolveSafelyHandlesSymlinks(@TempDir Path tempDir) throws Exception {
        Path insideTarget = Files.createFile(tempDir.resolve("target.bin"));
        Path safeSymlink = tempDir.resolve("safe-link.bin");

        try {
            Files.createSymbolicLink(safeSymlink, insideTarget);
            Path resolvedSafe = AdversarialPathGuard.resolveSafely(tempDir, "safe-link.bin");
            assertEquals(safeSymlink.toAbsolutePath().normalize(), resolvedSafe);
        } catch (UnsupportedOperationException | SecurityException e) {
            // Symlink creation might not be permitted in some restricted environments
            return;
        }

        // Test escaping symlink pointing outside tempDir
        Path outsideDir = Files.createTempDirectory("embedra-outside");
        try {
            Path outsideTarget = Files.createFile(outsideDir.resolve("escaped.bin"));
            Path evilSymlink = tempDir.resolve("evil-link.bin");
            Files.createSymbolicLink(evilSymlink, outsideTarget);

            DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                    AdversarialPathGuard.resolveSafely(tempDir, "evil-link.bin"));
            assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, ex.diagnostic().code());
            assertTrue(ex.getMessage().contains("escapes base directory"));
        } finally {
            deleteRecursively(outsideDir.toFile());
        }
    }

    @Test
    void testPrivateConstructor() throws Exception {
        Constructor<AdversarialPathGuard> constructor = AdversarialPathGuard.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        assertNotNull(constructor.newInstance());
    }

    private static void deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursively(child);
                }
            }
        }
        file.delete();
    }
}
