package io.github.rezabakhshi.embedra.pack;

import java.nio.file.Path;
import java.util.Objects;

/** One regular file declared by a pack manifest. */
public record PackFile(String path, long size, String sha256) {
    public PackFile {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(sha256, "sha256");
        if (!isSafeRelativePath(path)) {
            throw new IllegalArgumentException("Pack file path is unsafe");
        }
        if (size < 0) {
            throw new IllegalArgumentException("Pack file size must be non-negative");
        }
        if (!sha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Pack file digest must be lowercase SHA-256");
        }
    }

    static boolean isSafeRelativePath(String value) {
        if (value.isBlank() || value.indexOf('\\') >= 0 || value.startsWith("/")
            || value.matches("^[A-Za-z]:.*") || value.contains("//") || value.endsWith("/")) {
            return false;
        }
        Path path;
        try {
            path = Path.of(value);
        }
        catch (RuntimeException exception) {
            return false;
        }
        if (path.isAbsolute() || path.getNameCount() == 0 || !path.normalize().equals(path)) {
            return false;
        }
        for (Path component : path) {
            String name = component.toString();
            if (name.equals(".") || name.equals("..") || name.isBlank()) {
                return false;
            }
        }
        return !value.equals("pack.json");
    }
}
