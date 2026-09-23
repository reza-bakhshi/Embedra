package io.github.rezabakhshi.embedra.analyzers.esp;

/** Explicit distinction between crypto implementation and use-site evidence. */
public enum EspCryptoEvidenceKind {
    ALGORITHM_IMPLEMENTATION,
    WRAPPER_FUNCTION,
    CALLER_USE_SITE,
    ROM_API_CALLER,
    HARDWARE_ACCELERATOR_USE,
    CONSTANT_TABLE,
    IV_OR_NONCE,
    PUBLIC_KEY,
    POSSIBLE_SECRET_KEY,
    VERIFIED_KEY_OR_CERTIFICATE,
    HIGH_ENTROPY_DATA,
    CHECKSUM_OR_CRC,
    ENCODING,
    COMPRESSION
}
