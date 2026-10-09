package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

/**
 * Role of the detected cryptographic artifact (AN-014).
 *
 * <p>Strictly differentiates algorithm implementations, hardware wrappers, caller/use-sites,
 * inlined idioms, constant tables, key material candidates, certificates, and random generators.</p>
 */
public enum CryptoArtifactRole {
    ALGORITHM_IMPLEMENTATION("Algorithm Implementation"),
    WRAPPER("Library / Hardware Wrapper"),
    CALLER_USE_SITE("Caller / Use-Site Idiom"),
    INLINED_IDIOM("Inlined Algorithmic Idiom"),
    CONSTANT_TABLE("Constant Table Reference"),
    KEY_SCHEDULE("Key Schedule / Expansion"),
    IV_NONCE("IV / Nonce Handling"),
    PUBLIC_KEY("Public Key Operation"),
    SECRET_KEY_CANDIDATE("Secret Key Candidate"),
    CERTIFICATE("Certificate / Key Parser"),
    RANDOM_GENERATOR("Random Generator / DRBG"),
    PROTOCOL_ENCODING("Protocol / Framing Encoding");

    private final String displayName;

    CryptoArtifactRole(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
