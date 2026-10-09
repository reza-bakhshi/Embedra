package io.github.rezabakhshi.embedra.analyzers.crypto;

/**
 * High-level cryptographic and related artifact categories (AN-003, AN-010).
 *
 * <p>In accordance with AN-003, checksums/CRCs, encodings, compression, and entropy
 * anomalies alone MUST NOT be categorized or labeled as encryption.</p>
 */
public enum CryptoCategory {
    /**
     * Symmetric encryption ciphers (e.g. AES, DES, 3DES, ChaCha20, RC4).
     */
    CIPHER_SYMMETRIC("Symmetric Cipher", true),

    /**
     * Asymmetric public-key cryptography (e.g. RSA, ECC, Ed25519, Curve25519).
     */
    CIPHER_ASYMMETRIC("Asymmetric Cipher", true),

    /**
     * Cryptographic hash functions and MACs (e.g. SHA-256, SHA-512, MD5, HMAC, CMAC).
     */
    HASH_MAC("Hash / MAC", false),

    /**
     * Cyclic redundancy checks and checksums (e.g. CRC-32, CRC-16, CRC-8, Adler-32).
     * Must not be labeled encryption (AN-003).
     */
    CHECKSUM_CRC("Checksum / CRC", false),

    /**
     * Likely secret cryptographic key material (e.g. 128-bit, 192-bit, 256-bit symmetric keys).
     */
    KEY_MATERIAL("Key Material", false),

    /**
     * Cryptographic certificates and parsed public key credentials.
     */
    CERTIFICATE("Certificate", false),

    /**
     * High-entropy anomaly regions not yet attributed to a specific cipher or format.
     * Must not be labeled encryption (AN-003).
     */
    ENTROPY_ANOMALY("Entropy Anomaly", false),

    /**
     * Non-cryptographic data encodings and compression (e.g. Base64, Deflate, LZ4).
     * Strictly differentiated and excluded from encryption classification (AN-003).
     */
    ENCODING_OR_COMPRESSION("Encoding / Compression", false),

    /**
     * Hardware security peripheral or engine (eFuse, OTP, Secure Boot, Flash Encryption, Secure Element) (AN-013).
     */
    HARDWARE_SECURITY("Hardware Security", false),

    /**
     * Hardware or software random number generator (TRNG, PRNG, DRBG) (AN-012, AN-013).
     */
    RANDOM_GENERATOR("Random Generator", false);

    private final String displayName;

    private final boolean encryption;

    CryptoCategory(String displayName, boolean encryption) {
        this.displayName = displayName;
        this.encryption = encryption;
    }

    public String displayName() {
        return displayName;
    }

    /**
     * Returns true if and only if this category represents an encryption cipher (AN-003).
     */
    public boolean isEncryption() {
        return encryption;
    }
}
