package io.github.rezabakhshi.embedra.analyzers.esp;

/** Validation state of the optional SHA-256 digest appended to an ESP image. */
public enum EspImageHashState {
    ABSENT,
    VERIFIED,
    INVALID
}
