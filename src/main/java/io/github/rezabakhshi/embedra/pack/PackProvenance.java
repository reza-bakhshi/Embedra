package io.github.rezabakhshi.embedra.pack;

import java.net.URI;
import java.util.Objects;

/** Complete source and licensing provenance for one pack release. */
public record PackProvenance(
        URI source,
        String revision,
        String license,
        String transformation,
        RedistributionStatus redistribution) {
    public PackProvenance {
        Objects.requireNonNull(source, "source");
        requireText(revision, "revision");
        requireText(license, "license");
        requireText(transformation, "transformation");
        Objects.requireNonNull(redistribution, "redistribution");
        if (!source.isAbsolute() || source.getScheme() == null) {
            throw new IllegalArgumentException("Provenance source must be an absolute URI");
        }
    }

    private static void requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException("Provenance " + field + " must not be blank");
        }
    }
}
