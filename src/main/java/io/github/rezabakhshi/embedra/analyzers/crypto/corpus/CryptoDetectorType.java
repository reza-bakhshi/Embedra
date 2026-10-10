package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

/**
 * Functional taxonomy of individual cryptographic detection engines evaluated across the corpus (AN-010, AN-015).
 */
public enum CryptoDetectorType {
    /**
     * Constant and lookup table pattern matching engine (AES S-box, SHA constants, etc.).
     */
    CONSTANT_TABLE("Constant / Lookup Table"),

    /**
     * Byte-pattern and masked library/compiler signature matcher (mbedTLS, wolfSSL, ESP-IDF, etc.).
     */
    LIBRARY_SIGNATURE("Library / Function Signature"),

    /**
     * Memory-mapped hardware peripheral register and accelerator analyzer (AES, SHA, CRYP, RNG).
     */
    HARDWARE_PERIPHERAL("Hardware Peripheral Engine"),

    /**
     * Silicon vendor ROM routine and API call analyzer (ESP32 ROM, RP2040 lookup codes).
     */
    VENDOR_ROM("Vendor ROM API"),

    /**
     * Candidate symmetric key material scanner with pattern and entropy validation.
     */
    KEY_MATERIAL("Candidate Key Material"),

    /**
     * Sliding-window Shannon entropy and distribution scanner.
     */
    ENTROPY_ANALYSIS("Statistical Entropy Scanner"),

    /**
     * Unified multi-layer evidence fusion pipeline (combines all layers).
     */
    FUSED_PIPELINE("Full Layered Fusion Pipeline");

    private final String displayName;

    CryptoDetectorType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
