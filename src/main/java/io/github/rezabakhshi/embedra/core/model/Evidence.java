package io.github.rezabakhshi.embedra.core.model;

import java.util.Objects;

/** Immutable provenance statement kept separate from confidence. */
public record Evidence(EvidenceKind kind, String source, String detail) {
    public Evidence {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(detail, "detail");
        if (source.isBlank()) {
            throw new IllegalArgumentException("Evidence source must not be blank");
        }
        if (detail.isBlank()) {
            throw new IllegalArgumentException("Evidence detail must not be blank");
        }
    }
}
