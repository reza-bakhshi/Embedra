package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Built-in authoritative catalog of hardware cryptographic peripheral registers,
 * vendor ROM routines, and external secure elements (AN-010, AN-013).
 */
public final class HardwareCryptoCatalog {

    private static final List<HardwarePeripheralRegister> REGISTERS;

    private static final List<VendorRomCryptoRoutine> ROM_ROUTINES;

    private static final List<SecureElementDefinition> SECURE_ELEMENTS;

    private static final Map<Long, HardwarePeripheralRegister> REGISTERS_BY_ADDRESS;

    private static final Map<String, VendorRomCryptoRoutine> ROM_BY_LOOKUP_CODE;

    static {
        List<HardwarePeripheralRegister> regs = new ArrayList<>();
        List<VendorRomCryptoRoutine> roms = new ArrayList<>();
        List<SecureElementDefinition> ses = new ArrayList<>();

        // ==========================================
        // 1. ESP32-S3 Hardware Peripherals
        // ==========================================
        // AES Accelerator (base 0x6003A000)
        Map<Long, String> espAesModes = Map.of(
                0L, "AES-128-ECB",
                1L, "AES-192-ECB",
                2L, "AES-256-ECB"
        );
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-aes-mode", "AES", HardwareCryptoPlatform.ESP32_S3,
                0x6003_a040L, 4, CryptoAlgorithm.AES_128, HardwareCryptoFeature.SYMMETRIC_ACCELERATOR,
                false, espAesModes, "ESP32-S3 AES mode selection register"));
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-aes-trigger", "AES", HardwareCryptoPlatform.ESP32_S3,
                0x6003_a048L, 4, CryptoAlgorithm.AES_128, HardwareCryptoFeature.SYMMETRIC_ACCELERATOR,
                true, Map.of(1L, "TRIGGER_CALCULATION"), "ESP32-S3 AES calculation trigger register"));
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-aes-block-mode", "AES", HardwareCryptoPlatform.ESP32_S3,
                0x6003_a064L, 4, CryptoAlgorithm.AES_128, HardwareCryptoFeature.SYMMETRIC_ACCELERATOR,
                false, Map.of(0L, "ECB", 1L, "CBC", 2L, "OFB", 3L, "CTR", 6L, "GCM"),
                "ESP32-S3 AES block cipher mode register"));

        // SHA Accelerator (base 0x6003B000)
        Map<Long, String> espShaModes = Map.of(
                0L, "SHA-1",
                1L, "SHA-224",
                2L, "SHA-256",
                3L, "SHA-384",
                4L, "SHA-512"
        );
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-sha-mode", "SHA", HardwareCryptoPlatform.ESP32_S3,
                0x6003_b000L, 4, CryptoAlgorithm.SHA256, HardwareCryptoFeature.HASH_ACCELERATOR,
                false, espShaModes, "ESP32-S3 SHA mode selection register"));
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-sha-start", "SHA", HardwareCryptoPlatform.ESP32_S3,
                0x6003_b010L, 4, CryptoAlgorithm.SHA256, HardwareCryptoFeature.HASH_ACCELERATOR,
                true, Map.of(1L, "START_HASH"), "ESP32-S3 SHA calculation start trigger"));

        // RSA / PKA Accelerator (base 0x6003C000)
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-rsa-start", "RSA", HardwareCryptoPlatform.ESP32_S3,
                0x6003_c800L, 4, CryptoAlgorithm.RSA, HardwareCryptoFeature.ASYMMETRIC_ACCELERATOR,
                true, Map.of(1L, "START_MODEXP"), "ESP32-S3 RSA modular exponentiation start trigger"));

        // Digital Signature Peripheral (base 0x6003D000)
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-ds-start", "DS", HardwareCryptoPlatform.ESP32_S3,
                0x6003_d000L, 4, CryptoAlgorithm.RSA, HardwareCryptoFeature.DIGITAL_SIGNATURE,
                true, Map.of(1L, "START_SIGNATURE"), "ESP32-S3 Digital Signature start trigger"));

        // HMAC Peripheral (base 0x6003E000)
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-hmac-start", "HMAC", HardwareCryptoPlatform.ESP32_S3,
                0x6003_e000L, 4, CryptoAlgorithm.HMAC, HardwareCryptoFeature.HMAC_PERIPHERAL,
                true, Map.of(1L, "START_HMAC"), "ESP32-S3 HMAC calculation start trigger"));

        // Hardware TRNG (WCL / RNG base 0x600260B0)
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-rng-data", "RNG", HardwareCryptoPlatform.ESP32_S3,
                0x6002_60b0L, 4, CryptoAlgorithm.TRNG, HardwareCryptoFeature.TRNG_PERIPHERAL,
                false, Map.of(), "ESP32-S3 Hardware TRNG data sample register"));

        // eFuse Controller (base 0x60007000)
        regs.add(new HardwarePeripheralRegister(
                "esp32s3-efuse-blk0", "EFUSE", HardwareCryptoPlatform.ESP32_S3,
                0x6000_7000L, 4, CryptoAlgorithm.EFUSE_KEY_LADDER, HardwareCryptoFeature.EFUSE_OTP_KEY_LADDER,
                false, Map.of(), "ESP32-S3 eFuse Block 0 system configuration and key status"));

        // ==========================================
        // 2. STM32 Hardware Peripherals (F4, F7, H7, L4, L5, U5, WB)
        // ==========================================
        // CRYP (AES / DES hardware engine, base 0x50060000 on F4/F7/H7/L4)
        Map<Long, String> stmCrypModes = Map.of(
                0x00L, "TDES-ECB",
                0x04L, "TDES-CBC",
                0x08L, "DES-ECB",
                0x0CL, "DES-CBC",
                0x10L, "AES-ECB",
                0x14L, "AES-CBC",
                0x18L, "AES-CTR",
                0x20L, "AES-GCM"
        );
        regs.add(new HardwarePeripheralRegister(
                "stm32-cryp-cr", "CRYP", HardwareCryptoPlatform.STM32_F4,
                0x5006_0000L, 4, CryptoAlgorithm.AES_128, HardwareCryptoFeature.SYMMETRIC_ACCELERATOR,
                true, stmCrypModes, "STM32 CRYP control register and mode selection"));
        regs.add(new HardwarePeripheralRegister(
                "stm32-cryp-din", "CRYP", HardwareCryptoPlatform.STM32_F4,
                0x5006_0008L, 4, CryptoAlgorithm.AES_128, HardwareCryptoFeature.SYMMETRIC_ACCELERATOR,
                false, Map.of(), "STM32 CRYP data input FIFO register"));
        regs.add(new HardwarePeripheralRegister(
                "stm32-cryp-dout", "CRYP", HardwareCryptoPlatform.STM32_F4,
                0x5006_000cL, 4, CryptoAlgorithm.AES_128, HardwareCryptoFeature.SYMMETRIC_ACCELERATOR,
                false, Map.of(), "STM32 CRYP data output FIFO register"));

        // HASH (SHA-1 / SHA-256 / MD5 accelerator, base 0x50060400 on F4/F7/H7)
        Map<Long, String> stmHashModes = Map.of(
                0x00L, "SHA-1",
                0x20L, "MD5",
                0x40L, "SHA-224",
                0x60L, "SHA-256"
        );
        regs.add(new HardwarePeripheralRegister(
                "stm32-hash-cr", "HASH", HardwareCryptoPlatform.STM32_F4,
                0x5006_0400L, 4, CryptoAlgorithm.SHA256, HardwareCryptoFeature.HASH_ACCELERATOR,
                true, stmHashModes, "STM32 HASH control register and algorithm selection"));
        regs.add(new HardwarePeripheralRegister(
                "stm32-hash-din", "HASH", HardwareCryptoPlatform.STM32_F4,
                0x5006_0404L, 4, CryptoAlgorithm.SHA256, HardwareCryptoFeature.HASH_ACCELERATOR,
                false, Map.of(), "STM32 HASH data input register"));
        regs.add(new HardwarePeripheralRegister(
                "stm32-hash-str", "HASH", HardwareCryptoPlatform.STM32_F4,
                0x5006_0408L, 4, CryptoAlgorithm.SHA256, HardwareCryptoFeature.HASH_ACCELERATOR,
                true, Map.of(1L, "START_DIGEST"), "STM32 HASH start digest computation trigger"));

        // RNG (True Random Number Generator, base 0x50060800 on F4/F7/H7/L4)
        regs.add(new HardwarePeripheralRegister(
                "stm32-rng-cr", "RNG", HardwareCryptoPlatform.STM32_F4,
                0x5006_0800L, 4, CryptoAlgorithm.TRNG, HardwareCryptoFeature.TRNG_PERIPHERAL,
                true, Map.of(4L, "RNG_ENABLE"), "STM32 RNG control register"));
        regs.add(new HardwarePeripheralRegister(
                "stm32-rng-dr", "RNG", HardwareCryptoPlatform.STM32_F4,
                0x5006_0808L, 4, CryptoAlgorithm.TRNG, HardwareCryptoFeature.TRNG_PERIPHERAL,
                false, Map.of(), "STM32 RNG 32-bit random data sample register"));

        // PKA (Public Key Accelerator on STM32WB, STM32L5, STM32U5, base 0x58002000 / 0x420C2000)
        regs.add(new HardwarePeripheralRegister(
                "stm32-pka-cr", "PKA", HardwareCryptoPlatform.STM32_WB,
                0x5800_2000L, 4, CryptoAlgorithm.ECDSA, HardwareCryptoFeature.ASYMMETRIC_ACCELERATOR,
                true, Map.of(1L, "PKA_START"), "STM32 PKA control and operation start trigger"));

        // ==========================================
        // 3. RP2040 & RP2350 Hardware Accelerators
        // ==========================================
        // RP2350 SHA-256 Accelerator (base 0x400D0000)
        regs.add(new HardwarePeripheralRegister(
                "rp2350-sha256-ctrl", "SHA256", HardwareCryptoPlatform.RP2350,
                0x400d_0000L, 4, CryptoAlgorithm.SHA256, HardwareCryptoFeature.HASH_ACCELERATOR,
                true, Map.of(1L, "START"), "RP2350 hardware SHA-256 controller"));

        // RP2350 TRNG (base 0x400D8000)
        regs.add(new HardwarePeripheralRegister(
                "rp2350-trng-sample", "TRNG", HardwareCryptoPlatform.RP2350,
                0x400d_8000L, 4, CryptoAlgorithm.TRNG, HardwareCryptoFeature.TRNG_PERIPHERAL,
                false, Map.of(), "RP2350 hardware TRNG random word sample register"));

        // RP2350 OTP Memory (base 0x400E0000)
        regs.add(new HardwarePeripheralRegister(
                "rp2350-otp-data", "OTP", HardwareCryptoPlatform.RP2350,
                0x400e_0000L, 4, CryptoAlgorithm.EFUSE_KEY_LADDER, HardwareCryptoFeature.EFUSE_OTP_KEY_LADDER,
                false, Map.of(), "RP2350 OTP security configuration and boot keys"));

        // ==========================================
        // 4. Vendor ROM Cryptographic Routines
        // ==========================================
        // RP2040 Boot ROM exported functions (via 'RE', 'RP', 'FC', etc.)
        roms.add(new VendorRomCryptoRoutine(
                "rp2040-rom-re", "flash_range_erase", HardwareCryptoPlatform.RP2040,
                -1, "RE", CryptoAlgorithm.FLASH_ENCRYPTION, HardwareCryptoFeature.VENDOR_ROM_API,
                "RP2040 ROM flash range erase (potential bootloader write site)"));
        roms.add(new VendorRomCryptoRoutine(
                "rp2040-rom-rp", "flash_range_program", HardwareCryptoPlatform.RP2040,
                -1, "RP", CryptoAlgorithm.FLASH_ENCRYPTION, HardwareCryptoFeature.VENDOR_ROM_API,
                "RP2040 ROM flash range program"));

        // ESP32-S3 Mask ROM SHA/AES/RSA routines
        roms.add(new VendorRomCryptoRoutine(
                "esp32s3-rom-sha1", "ets_sha_enable", HardwareCryptoPlatform.ESP32_S3,
                0x4000_0700L, null, CryptoAlgorithm.SHA1, HardwareCryptoFeature.VENDOR_ROM_API,
                "ESP32-S3 Mask ROM SHA hardware enable"));
        roms.add(new VendorRomCryptoRoutine(
                "esp32s3-rom-sha256", "ets_sha256_process", HardwareCryptoPlatform.ESP32_S3,
                0x4000_0720L, null, CryptoAlgorithm.SHA256, HardwareCryptoFeature.VENDOR_ROM_API,
                "ESP32-S3 Mask ROM SHA-256 process block"));
        roms.add(new VendorRomCryptoRoutine(
                "esp32s3-rom-aes", "ets_aes_crypt", HardwareCryptoPlatform.ESP32_S3,
                0x4000_0800L, null, CryptoAlgorithm.AES_128, HardwareCryptoFeature.VENDOR_ROM_API,
                "ESP32-S3 Mask ROM AES encryption/decryption routine"));
        roms.add(new VendorRomCryptoRoutine(
                "esp32s3-rom-secboot", "ets_secure_boot_verify_signature", HardwareCryptoPlatform.ESP32_S3,
                0x4000_0900L, null, CryptoAlgorithm.SECURE_BOOT, HardwareCryptoFeature.SECURE_BOOT_ENGINE,
                "ESP32-S3 Mask ROM secure boot signature verification"));

        // ==========================================
        // 5. External Secure Elements
        // ==========================================
        ses.add(new SecureElementDefinition(
                "ATECC608A", "Microchip", "ATECC608A", 0x60,
                CryptoAlgorithm.ECDSA, "Microchip CryptoAuthentication Secure Element (I2C default 0x60 / 0xC0)"));
        ses.add(new SecureElementDefinition(
                "ATECC608B", "Microchip", "ATECC608B", 0x35,
                CryptoAlgorithm.ECDSA, "Microchip CryptoAuthentication Secure Element (I2C 0x35)"));
        ses.add(new SecureElementDefinition(
                "OPTIGA_TRUST_M", "Infineon", "OPTIGA Trust M", 0x30,
                CryptoAlgorithm.ECDSA, "Infineon OPTIGA Trust M hardware security controller (I2C 0x30)"));
        ses.add(new SecureElementDefinition(
                "SE050", "NXP", "EdgeLock SE050", 0x48,
                CryptoAlgorithm.ECC_P256, "NXP EdgeLock SE050 Plug & Trust Secure Element (I2C 0x48)"));

        // Build index maps
        Map<Long, HardwarePeripheralRegister> regMap = new HashMap<>();
        for (HardwarePeripheralRegister r : regs) {
            regMap.put(r.address(), r);
        }

        Map<String, VendorRomCryptoRoutine> codeMap = new HashMap<>();
        for (VendorRomCryptoRoutine r : roms) {
            if (r.lookupCode() != null) {
                codeMap.put(r.lookupCode(), r);
            }
        }

        REGISTERS = Collections.unmodifiableList(regs);
        ROM_ROUTINES = Collections.unmodifiableList(roms);
        SECURE_ELEMENTS = Collections.unmodifiableList(ses);
        REGISTERS_BY_ADDRESS = Collections.unmodifiableMap(regMap);
        ROM_BY_LOOKUP_CODE = Collections.unmodifiableMap(codeMap);
    }

    private HardwareCryptoCatalog() {
    }

    public static List<HardwarePeripheralRegister> registers() {
        return REGISTERS;
    }

    public static List<VendorRomCryptoRoutine> romRoutines() {
        return ROM_ROUTINES;
    }

    public static List<SecureElementDefinition> secureElements() {
        return SECURE_ELEMENTS;
    }

    public static Optional<HardwarePeripheralRegister> findRegisterByAddress(long address) {
        return Optional.ofNullable(REGISTERS_BY_ADDRESS.get(address));
    }

    public static Optional<VendorRomCryptoRoutine> findRomByLookupCode(String code) {
        if (code == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(ROM_BY_LOOKUP_CODE.get(code));
    }

    public static Optional<VendorRomCryptoRoutine> findRomByName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        for (VendorRomCryptoRoutine r : ROM_ROUTINES) {
            String rLower = r.routineName().toLowerCase(java.util.Locale.ROOT);
            if (r.routineName().equalsIgnoreCase(lower) || lower.contains(rLower)) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }
}
