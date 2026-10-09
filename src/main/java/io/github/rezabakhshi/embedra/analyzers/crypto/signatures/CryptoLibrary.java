package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

/**
 * Standard embedded cryptographic libraries recognized by signature analysis (AN-011).
 */
public enum CryptoLibrary {
    MBEDTLS("mbed TLS / PSA Crypto"),
    WOLFSSL("wolfSSL"),
    BEARSSL("BearSSL"),
    TINYCRYPT("TinyCrypt"),
    MONOCYPHER("Monocypher"),
    MICRO_ECC("micro-ecc"),
    LIBTOMCRYPT("LibTomCrypt"),
    OPENSSL("OpenSSL"),
    ESP_IDF("ESP-IDF / ESP-TLS Crypto"),
    STM32_HAL("STM32 HAL/LL Crypto"),
    PICO_SDK("Raspberry Pi Pico SDK Crypto"),
    CUSTOM("Custom / Third-Party Crypto");

    private final String displayName;

    CryptoLibrary(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
