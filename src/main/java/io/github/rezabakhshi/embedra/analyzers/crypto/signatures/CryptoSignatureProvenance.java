package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Provenance tracking for cryptographic signatures (AN-011, CORE-013).
 */
public record CryptoSignatureProvenance(
        String library,
        String version,
        String license,
        String sourceFile,
        String sourceSha256) {

    private static final Pattern SHA256_PATTERN = Pattern.compile("^[0-9a-f]{64}$");

    public CryptoSignatureProvenance {
        Objects.requireNonNull(library, "library must not be null");
        Objects.requireNonNull(version, "version must not be null");
        Objects.requireNonNull(license, "license must not be null");
        Objects.requireNonNull(sourceFile, "sourceFile must not be null");
        Objects.requireNonNull(sourceSha256, "sourceSha256 must not be null");

        if (library.isBlank()) {
            throw new IllegalArgumentException("library must not be blank");
        }
        if (version.isBlank()) {
            throw new IllegalArgumentException("version must not be blank");
        }
        if (license.isBlank()) {
            throw new IllegalArgumentException("license must not be blank");
        }
        if (sourceFile.isBlank()) {
            throw new IllegalArgumentException("sourceFile must not be blank");
        }
        if (!SHA256_PATTERN.matcher(sourceSha256).matches()) {
            throw new IllegalArgumentException("sourceSha256 must be lowercase 64-hex SHA-256 digest: " + sourceSha256);
        }
    }
}
