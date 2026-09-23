package io.github.rezabakhshi.embedra.analyzers.esp;

/** Conservative classification of one supplied PNG candidate byte range. */
public enum PngCandidateStatus {
    NOT_PNG,
    SIGNATURE_COLLISION,
    TRUNCATED,
    INVALID_HEADER,
    INVALID_CRC,
    UNSUPPORTED,
    RESOURCE_LIMIT,
    VALID
}
