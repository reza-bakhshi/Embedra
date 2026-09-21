package io.github.rezabakhshi.embedra.core.model;

/** Provenance category for an individual piece of analysis evidence. */
public enum EvidenceKind {
    DOCUMENTED_FIELD,
    VERIFIED_CHECKSUM,
    VENDOR_DATA_PACK,
    EXACT_SIGNATURE_MATCH,
    DERIVED_RULE,
    HEURISTIC,
    USER_ASSERTION
}
