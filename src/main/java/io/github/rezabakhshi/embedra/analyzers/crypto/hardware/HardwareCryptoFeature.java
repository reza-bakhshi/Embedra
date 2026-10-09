package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

/**
 * Functional hardware subsystem or feature category (AN-013).
 */
public enum HardwareCryptoFeature {
    /**
     * Hardware symmetric cipher accelerator (e.g. AES-128/192/256, DES).
     */
    SYMMETRIC_ACCELERATOR("Hardware Symmetric Accelerator"),

    /**
     * Hardware cryptographic hash accelerator (e.g. SHA-1, SHA-256, SHA-512).
     */
    HASH_ACCELERATOR("Hardware Hash Accelerator"),

    /**
     * Hardware public-key accelerator (e.g. RSA, ECC, PKA, ECDSA).
     */
    ASYMMETRIC_ACCELERATOR("Hardware Asymmetric Accelerator (PKA/RSA)"),

    /**
     * Hardware or digital signature peripheral (e.g. ESP32 DS peripheral).
     */
    DIGITAL_SIGNATURE("Digital Signature Peripheral"),

    /**
     * Hardware HMAC peripheral.
     */
    HMAC_PERIPHERAL("Hardware HMAC Peripheral"),

    /**
     * True Random Number Generator hardware peripheral.
     */
    TRNG_PERIPHERAL("Hardware TRNG Peripheral"),

    /**
     * eFuse controller, OTP memory, or hardware key-ladder block.
     */
    EFUSE_OTP_KEY_LADDER("eFuse / OTP / Key Ladder Controller"),

    /**
     * Transparent on-the-fly flash encryption engine (e.g. ESP32 Flash Encryption, STM32 OTFDEC).
     */
    FLASH_ENCRYPTION_ENGINE("Flash Encryption Engine"),

    /**
     * Hardware secure boot verification or public key digest storage.
     */
    SECURE_BOOT_ENGINE("Hardware Secure Boot Engine"),

    /**
     * External secure element interface (e.g. ATECC608A/B, Optiga Trust, SE050 via I2C/SPI).
     */
    SECURE_ELEMENT_BUS("Secure Element Bus Interface"),

    /**
     * Masked vendor ROM cryptographic API routine.
     */
    VENDOR_ROM_API("Vendor Mask ROM API Routine");

    private final String displayName;

    HardwareCryptoFeature(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
