package io.github.rezabakhshi.embedra.targets.esp.catalog;

import java.util.Objects;

/** Immutable identity and redistribution disposition for one catalog source. */
public record EspCatalogSource(
        String identity,
        String url,
        String revision,
        String sha256,
        String license,
        String redistribution) {
    public EspCatalogSource {
        require(identity, "identity");
        require(url, "url");
        require(revision, "revision");
        require(sha256, "sha256");
        require(license, "license");
        require(redistribution, "redistribution");
        if (!sha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Source SHA-256 must be lowercase hexadecimal");
        }
    }

    private static void require(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
