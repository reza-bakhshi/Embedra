package io.github.rezabakhshi.embedra.analyzers.stm32;

import java.util.Objects;

/** Stable, explicit reason that a signature pack produced no match. */
public record Stm32SignatureNonMatch(Kind kind, String detail) {
    /** Why no signature was applied. */
    public enum Kind {
        /** Compiler, optimization, or family evidence was not recorded. */
        EVIDENCE_MISSING,
        /** No signature in the pack is indexed for the recorded evidence. */
        INDEX_UNAVAILABLE,
        /** The recorded evidence was present but no candidate function matched. */
        NO_MATCH
    }

    public Stm32SignatureNonMatch {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(detail, "detail");
        if (detail.isBlank()) {
            throw new IllegalArgumentException("Non-match detail must not be blank");
        }
    }
}
