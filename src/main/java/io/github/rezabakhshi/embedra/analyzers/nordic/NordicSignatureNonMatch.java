package io.github.rezabakhshi.embedra.analyzers.nordic;

import java.util.Objects;

/** Stable, explicit reason that a Nordic signature pack produced no match (NRF-009, NRF-010). */
public record NordicSignatureNonMatch(Kind kind, String detail) {

    /** Why no signature was applied. */
    public enum Kind {
        /** Series or exact part evidence was not recorded. */
        EVIDENCE_MISSING,
        /** No signature in the pack is indexed for the recorded evidence. */
        INDEX_UNAVAILABLE,
        /** The recorded evidence was present but no candidate function matched. */
        NO_MATCH
    }

    public NordicSignatureNonMatch {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(detail, "detail");
        if (detail.isBlank()) {
            throw new IllegalArgumentException("Non-match detail must not be blank");
        }
    }
}
