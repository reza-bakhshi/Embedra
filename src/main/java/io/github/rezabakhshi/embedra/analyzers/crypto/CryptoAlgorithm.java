package io.github.rezabakhshi.embedra.analyzers.crypto;

/**
 * Standard cryptographic algorithms, primitives, checksums, and differentiated formats (AN-003, AN-012).
 */
public enum CryptoAlgorithm {
    // Symmetric ciphers
    AES_128("AES-128", CryptoCategory.CIPHER_SYMMETRIC),
    AES_192("AES-192", CryptoCategory.CIPHER_SYMMETRIC),
    AES_256("AES-256", CryptoCategory.CIPHER_SYMMETRIC),
    DES("DES", CryptoCategory.CIPHER_SYMMETRIC),
    TRIPLE_DES("3DES", CryptoCategory.CIPHER_SYMMETRIC),
    CHACHA20("ChaCha20", CryptoCategory.CIPHER_SYMMETRIC),
    CHACHA20_POLY1305("ChaCha20-Poly1305", CryptoCategory.CIPHER_SYMMETRIC),
    RC4("RC4", CryptoCategory.CIPHER_SYMMETRIC),

    // Asymmetric ciphers & curves
    RSA("RSA", CryptoCategory.CIPHER_ASYMMETRIC),
    DIFFIE_HELLMAN("Diffie-Hellman", CryptoCategory.CIPHER_ASYMMETRIC),
    ECC_P256("NIST P-256", CryptoCategory.CIPHER_ASYMMETRIC),
    ECC_SECP256K1("secp256k1", CryptoCategory.CIPHER_ASYMMETRIC),
    ECDSA("ECDSA", CryptoCategory.CIPHER_ASYMMETRIC),
    ECDH("ECDH", CryptoCategory.CIPHER_ASYMMETRIC),
    CURVE25519("Curve25519", CryptoCategory.CIPHER_ASYMMETRIC),
    ED25519("Ed25519", CryptoCategory.CIPHER_ASYMMETRIC),
    X25519("X25519", CryptoCategory.CIPHER_ASYMMETRIC),

    // Hashes & MACs
    MD5("MD5", CryptoCategory.HASH_MAC),
    SHA1("SHA-1", CryptoCategory.HASH_MAC),
    SHA224("SHA-224", CryptoCategory.HASH_MAC),
    SHA256("SHA-256", CryptoCategory.HASH_MAC),
    SHA384("SHA-384", CryptoCategory.HASH_MAC),
    SHA512("SHA-512", CryptoCategory.HASH_MAC),
    SHA3("SHA-3", CryptoCategory.HASH_MAC),
    BLAKE2B("BLAKE2b", CryptoCategory.HASH_MAC),
    BLAKE2S("BLAKE2s", CryptoCategory.HASH_MAC),
    POLY1305("Poly1305", CryptoCategory.HASH_MAC),
    HMAC("HMAC", CryptoCategory.HASH_MAC),
    CMAC("CMAC", CryptoCategory.HASH_MAC),
    HKDF("HKDF", CryptoCategory.HASH_MAC),
    PBKDF2("PBKDF2", CryptoCategory.HASH_MAC),
    DRBG_PRNG("DRBG / PRNG", CryptoCategory.RANDOM_GENERATOR),
    TRNG("Hardware TRNG", CryptoCategory.RANDOM_GENERATOR),
    ASN1_KEY_CERT_PARSER("Key/Certificate Parser", CryptoCategory.CERTIFICATE),
    SECURE_BOOT("Secure Boot Engine", CryptoCategory.HARDWARE_SECURITY),
    FLASH_ENCRYPTION("Flash Encryption Controller", CryptoCategory.HARDWARE_SECURITY),
    EFUSE_KEY_LADDER("eFuse / Key-Ladder / OTP", CryptoCategory.HARDWARE_SECURITY),
    SECURE_ELEMENT("Hardware Secure Element / ATECC", CryptoCategory.HARDWARE_SECURITY),

    // Checksums & CRCs (not encryption - AN-003)
    CRC32("CRC-32", CryptoCategory.CHECKSUM_CRC),
    CRC16("CRC-16", CryptoCategory.CHECKSUM_CRC),
    CRC8("CRC-8", CryptoCategory.CHECKSUM_CRC),
    ADLER32("Adler-32", CryptoCategory.CHECKSUM_CRC),
    FLETCHER16("Fletcher-16", CryptoCategory.CHECKSUM_CRC),

    // Key material & certificates
    GENERIC_KEY("Candidate Key", CryptoCategory.KEY_MATERIAL),
    GENERIC_CERTIFICATE("Certificate", CryptoCategory.CERTIFICATE),

    // Entropy anomaly (not encryption - AN-003)
    HIGH_ENTROPY_BLOCK("High Entropy Data", CryptoCategory.ENTROPY_ANOMALY),

    // Encodings & Compression (differentiated non-crypto - AN-003)
    BASE64("Base64", CryptoCategory.ENCODING_OR_COMPRESSION),
    DEFLATE_ZLIB("Deflate / zlib", CryptoCategory.ENCODING_OR_COMPRESSION),
    LZ4("LZ4", CryptoCategory.ENCODING_OR_COMPRESSION),

    // Unattributed
    UNKNOWN("Unknown Primitives", CryptoCategory.ENTROPY_ANOMALY);

    private final String displayName;

    private final CryptoCategory defaultCategory;

    CryptoAlgorithm(String displayName, CryptoCategory defaultCategory) {
        this.displayName = displayName;
        this.defaultCategory = defaultCategory;
    }

    public String displayName() {
        return displayName;
    }

    public CryptoCategory defaultCategory() {
        return defaultCategory;
    }
}
