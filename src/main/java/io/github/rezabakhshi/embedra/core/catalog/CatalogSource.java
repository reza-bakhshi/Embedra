package io.github.rezabakhshi.embedra.core.catalog;

import java.util.Objects;

/** Versioned catalog provenance without generation timestamps or host paths. */
public record CatalogSource(String identity, String revision, String license, String provenance) {
    public CatalogSource {
        requireText(identity, "identity");
        requireText(revision, "revision");
        requireText(license, "license");
        requireText(provenance, "provenance");
    }

    private static void requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException("Catalog source " + name + " must not be blank");
        }
    }
}
