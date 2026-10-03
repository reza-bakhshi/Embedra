package io.github.rezabakhshi.embedra.analyzers.ctf;

/**
 * Top-level classification category for discovered CTF and firmware entities (AN-002).
 */
public enum CtfEntityCategory {
    ENDPOINT,
    CREDENTIAL,
    CERTIFICATE_KEY,
    UUID,
    ENCODED_BLOB,
    FLAG
}
