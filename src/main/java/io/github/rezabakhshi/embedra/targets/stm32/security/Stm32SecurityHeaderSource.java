package io.github.rezabakhshi.embedra.targets.stm32.security;

import java.util.Objects;

/**
 * Provenance of one pinned redistributable CMSIS device header.
 *
 * <p>The repository, 40-hex commit, repository-relative path, and SHA-256 are
 * the exact upstream revision; the license is the reviewed redistribution
 * license. No vendor header bytes are bundled by this record.</p>
 */
public record Stm32SecurityHeaderSource(String repository, String commit, String path,
        String sha256, String license) {
    public Stm32SecurityHeaderSource {
        Objects.requireNonNull(repository, "repository");
        Objects.requireNonNull(commit, "commit");
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(license, "license");
        if (!repository.startsWith("https://") || repository.contains("..")) {
            throw new IllegalArgumentException("Security header repository is unsafe");
        }
        if (!commit.matches("[0-9a-f]{40}")) {
            throw new IllegalArgumentException("Security header commit is not pinned");
        }
        if (path.isBlank() || path.startsWith("/") || path.contains("..")) {
            throw new IllegalArgumentException("Security header path is unsafe");
        }
        if (!sha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Security header digest is not SHA-256");
        }
        if (license.isBlank()) {
            throw new IllegalArgumentException("Security header license is blank");
        }
    }
}
