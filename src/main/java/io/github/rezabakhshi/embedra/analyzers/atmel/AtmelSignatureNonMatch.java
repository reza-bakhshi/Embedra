package io.github.rezabakhshi.embedra.analyzers.atmel;

import java.util.Objects;

/** Stable, explicit reason that an Atmel/Microchip signature pack produced no match. */
public record AtmelSignatureNonMatch(Kind kind, String detail) {

    /** Why no signature was applied. */
    public enum Kind {
        /** Architecture, series, or exact part evidence was not recorded. */
        EVIDENCE_MISSING,
        /** No signature in the pack is indexed for the recorded evidence. */
        INDEX_UNAVAILABLE,
        /** The recorded evidence was present but no candidate function matched. */
        NO_MATCH
    }

    public AtmelSignatureNonMatch {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(detail, "detail");
        if (detail.isBlank()) {
            throw new IllegalArgumentException("Non-match detail must not be blank");
        }
    }
}
