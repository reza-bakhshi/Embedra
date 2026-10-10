package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.CrossProgramCryptoReference;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCallSite;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCryptoPlatform;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareMemoryAccess;
import io.github.rezabakhshi.embedra.analyzers.crypto.signatures.CryptoIsa;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.Set;

/**
 * Authoritative factory and repository for positive and negative cryptographic corpora (AN-003, AN-010, AN-015).
 *
 * <p>Spans ESP, STM32, RP2040, and RP2350 ISAs, compilers, hardware accelerators, constant tables,
 * adversarial non-crypto lookup tables, compressed streams, and documented unsupported variants.</p>
 */
public final class CryptoCorpus {

    private static final CryptoCorpus DEFAULT_CORPUS = buildDefaultCorpus();

    private final List<CryptoCorpusSample> samples;

    public CryptoCorpus(List<CryptoCorpusSample> samples) {
        Objects.requireNonNull(samples, "samples must not be null");
        this.samples = Collections.unmodifiableList(List.copyOf(samples));
    }

    public static CryptoCorpus defaultCorpus() {
        return DEFAULT_CORPUS;
    }

    public List<CryptoCorpusSample> allSamples() {
        return samples;
    }

    public List<CryptoCorpusSample> positiveSamples() {
        return samples.stream()
                .filter(s -> s.classification() == CryptoCorpusClassification.POSITIVE)
                .toList();
    }

    public List<CryptoCorpusSample> negativeSamples() {
        return samples.stream()
                .filter(s -> s.classification() == CryptoCorpusClassification.NEGATIVE_ADVERSARIAL)
                .toList();
    }

    public List<CryptoCorpusSample> unsupportedSamples() {
        return samples.stream()
                .filter(s -> s.classification() == CryptoCorpusClassification.UNSUPPORTED_VARIANT)
                .toList();
    }

    private static CryptoCorpus buildDefaultCorpus() {
        List<CryptoCorpusSample> list = new ArrayList<>();
        HexFormat hex = HexFormat.of();

        // Pinned AES forward S-box (first 64 bytes)
        byte[] aesSbox64 = hex.parseHex(
                "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
                + "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275");

        // Pinned AES inverse S-box (first 64 bytes)
        byte[] aesInvSbox64 = hex.parseHex(
                "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
                + "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125");

        // Pinned AES Rcon (10 bytes)
        byte[] aesRcon = hex.parseHex("01020408102040801b36");

        // Pinned SHA-256 K constants (first 64 bytes in little-endian format)
        byte[] sha256K = hex.parseHex(
                "982f8a4291443771cffbc0b5a5dbb5e9"
                + "5bc25639f111f159a4823f92d55e1cab"
                + "98aa07d8015b8312be853124c37d0c55"
                + "745dbe72feb1de80a706dc9b74f19bc1");

        // High entropy 128-bit and 256-bit candidate keys (AN-008, AN-014)
        byte[] key128A = hex.parseHex("5a3b8c1d4e2f9076123456789abcdef0");
        byte[] key128B = hex.parseHex("9f8e7d6c5b4a39281726354859607182");
        byte[] key256A = hex.parseHex("9f8e7d6c5b4a39281726354859607182a3b4c5d6e7f8091a2b3c4d5e6f708192");
        byte[] key256B = hex.parseHex("f0e1d2c3b4a5968778695a4b3c2d1e0f8192a3b4c5d6e7f81a2b3c4d5e6f7089");

        // =====================================================================
        // SECTION 1: POSITIVE CORPORA (ESP, STM32, RP2040, RP2350)
        // =====================================================================

        // 1. ESP32 Xtensa AES via mbedTLS and Hardware MMIO
        ByteArrayOutputStream esp32Payload = new ByteArrayOutputStream();
        esp32Payload.writeBytes(aesSbox64);
        esp32Payload.writeBytes(key128A);
        list.add(new CryptoCorpusSample(
                "esp32-pos-aes-hw-mbedtls",
                "ESP32 Xtensa AES-128 via mbedTLS and Hardware MMIO",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.ESP32,
                CryptoIsa.XTENSA,
                "Xtensa-ESP-ELF GCC 12.2.0 -O2",
                esp32Payload.toByteArray(),
                0x40001000L,
                List.of("mbedtls_aes_crypt_ecb"),
                List.of(
                        HardwareMemoryAccess.write(0x40001000L, 0x3ff01004L, 0L),
                        HardwareMemoryAccess.write(0x40001008L, 0x3ff01000L, 1L)
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.AES_128, CryptoAlgorithm.GENERIC_KEY),
                Set.of(CryptoDetectorType.CONSTANT_TABLE, CryptoDetectorType.KEY_MATERIAL,
                        CryptoDetectorType.HARDWARE_PERIPHERAL, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "ESP32 hardware AES trigger write corroborated with S-box table and candidate 128-bit key"
        ));

        // 2. ESP32-S3 Xtensa AES, SHA, and Vendor ROM API via ESP-IDF
        ByteArrayOutputStream esp32s3Payload = new ByteArrayOutputStream();
        esp32s3Payload.writeBytes(hex.parseHex("3641002012003100")); // esp_aes_crypt_ecb signature
        esp32s3Payload.writeBytes(sha256K);
        esp32s3Payload.writeBytes(key256A);
        list.add(new CryptoCorpusSample(
                "esp32s3-pos-aes-sha-espidf",
                "ESP32-S3 Xtensa AES & SHA Accelerator with ESP-IDF Wrappers and ROM Call",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.ESP32_S3,
                CryptoIsa.XTENSA,
                "Xtensa-ESP-ELF GCC 12.2.0 -Os",
                esp32s3Payload.toByteArray(),
                0x42000000L,
                List.of("esp_aes_crypt_ecb", "esp_sha256"),
                List.of(
                        HardwareMemoryAccess.write(0x42000000L, 0x6003a040L, 0L), // AES-128
                        HardwareMemoryAccess.write(0x42000008L, 0x6003a064L, 1L), // CBC
                        HardwareMemoryAccess.write(0x42000010L, 0x6003a048L, 1L)  // Trigger
                ),
                List.of(new HardwareCallSite(0x42000100L, 0x40000720L, "ets_sha256_process", List.of())),
                List.of(),
                Set.of(CryptoAlgorithm.AES_128, CryptoAlgorithm.SHA256, CryptoAlgorithm.GENERIC_KEY),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.CONSTANT_TABLE,
                        CryptoDetectorType.KEY_MATERIAL, CryptoDetectorType.HARDWARE_PERIPHERAL,
                        CryptoDetectorType.VENDOR_ROM, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "ESP32-S3 hardware AES CBC accelerator trigger, SHA-256 K constants, ROM call, and candidate key"
        ));

        // 3. ESP32-C3 RISC-V SHA Accelerator and ESP-IDF AES Wrapper
        ByteArrayOutputStream esp32c3Payload = new ByteArrayOutputStream();
        esp32c3Payload.writeBytes(hex.parseHex("130101ff23261100")); // esp_aes_crypt_ecb_rv signature
        esp32c3Payload.writeBytes(aesSbox64);
        list.add(new CryptoCorpusSample(
                "esp32c3-pos-sha-espidf",
                "ESP32-C3 RISC-V 32 SHA Engine and ESP-IDF AES Wrapper",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.ESP32_C3,
                CryptoIsa.RISCV32,
                "RISC-V GCC 12.2.0 -O2",
                esp32c3Payload.toByteArray(),
                0x40380000L,
                List.of("esp_aes_crypt_ecb_rv", "mbedtls_sha256"),
                List.of(
                        HardwareMemoryAccess.write(0x40380000L, 0x6003b000L, 2L), // SHA-256 mode
                        HardwareMemoryAccess.write(0x40380004L, 0x6003b004L, 1L)  // SHA start
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.AES_128, CryptoAlgorithm.SHA256),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.CONSTANT_TABLE,
                        CryptoDetectorType.HARDWARE_PERIPHERAL, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "ESP32-C3 RISC-V hardware SHA engine write, AES-128 signature, and forward S-box table"
        ));

        // 4. ESP32-C6 RISC-V ECC & HMAC Accelerator with Candidate Key
        ByteArrayOutputStream esp32c6Payload = new ByteArrayOutputStream();
        esp32c6Payload.writeBytes(key256B);
        list.add(new CryptoCorpusSample(
                "esp32c6-pos-ecc-hmac",
                "ESP32-C6 RISC-V 32 ECC Accelerator & HMAC Key Material",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.ESP32_C6,
                CryptoIsa.RISCV32,
                "RISC-V GCC 12.2.0 -O2",
                esp32c6Payload.toByteArray(),
                0x40800000L,
                List.of("esp_ecc_point_multiply", "mbedtls_hmac"),
                List.of(
                        HardwareMemoryAccess.write(0x40800000L, 0x6003c004L, 1L) // ECC trigger
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.ECDSA, CryptoAlgorithm.GENERIC_KEY),
                Set.of(CryptoDetectorType.HARDWARE_PERIPHERAL, CryptoDetectorType.KEY_MATERIAL,
                        CryptoDetectorType.FUSED_PIPELINE),
                null,
                "ESP32-C6 hardware ECC accelerator trigger with high-entropy candidate HMAC key"
        ));

        // 5. STM32F4 ARM Cortex-M4 CRYP AES-ECB & HAL Wrapper
        ByteArrayOutputStream stm32f4Payload = new ByteArrayOutputStream();
        stm32f4Payload.writeBytes(hex.parseHex("b510480368002800")); // HAL_CRYP_AESECB_Encrypt
        stm32f4Payload.writeBytes(aesSbox64);
        list.add(new CryptoCorpusSample(
                "stm32f4-pos-cryp-aes-hal",
                "STM32F4 ARM Cortex-M4 CRYP AES-ECB Peripheral & HAL Wrapper",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.STM32_F4,
                CryptoIsa.ARM_THUMB,
                "Arm GNU GCC 12.3.1 -O2",
                stm32f4Payload.toByteArray(),
                0x08001000L,
                List.of("HAL_CRYP_AESECB_Encrypt"),
                List.of(
                        HardwareMemoryAccess.write(0x08001000L, 0x50060000L, 0x10L) // CRYP CR AES-ECB
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.AES_128),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.CONSTANT_TABLE,
                        CryptoDetectorType.HARDWARE_PERIPHERAL, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "STM32F4 hardware CRYP AES-ECB peripheral trigger, HAL wrapper signature, and forward S-box"
        ));

        // 6. STM32F7 ARM Cortex-M7 HASH SHA-256 & mbedTLS
        ByteArrayOutputStream stm32f7Payload = new ByteArrayOutputStream();
        stm32f7Payload.writeBytes(hex.parseHex("2de9f04fb0b52446")); // mbedtls_sha256_process
        stm32f7Payload.writeBytes(sha256K);
        stm32f7Payload.writeBytes(key256A);
        list.add(new CryptoCorpusSample(
                "stm32f7-pos-hash-sha256-mbedtls",
                "STM32F7 ARM Cortex-M7 HASH Peripheral & mbedTLS SHA-256",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.STM32_F7,
                CryptoIsa.ARM_THUMB,
                "Arm GNU GCC 12.3.1 -O2",
                stm32f7Payload.toByteArray(),
                0x08002000L,
                List.of("mbedtls_sha256_process"),
                List.of(
                        HardwareMemoryAccess.write(0x08002020L, 0x50060400L, 0x60L) // HASH CR SHA-256
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.SHA256, CryptoAlgorithm.GENERIC_KEY),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.CONSTANT_TABLE,
                        CryptoDetectorType.KEY_MATERIAL, CryptoDetectorType.HARDWARE_PERIPHERAL,
                        CryptoDetectorType.FUSED_PIPELINE),
                null,
                "STM32F7 hardware HASH accelerator SHA-256 trigger, mbedTLS signature, constants, and key"
        ));

        // 7. STM32H7 ARM Cortex-M7 CRYP & Hardware RNG
        ByteArrayOutputStream stm32h7Payload = new ByteArrayOutputStream();
        stm32h7Payload.writeBytes(hex.parseHex("b508480468002000")); // HAL_RNG_GenerateRandomNumber
        stm32h7Payload.writeBytes(aesRcon);
        list.add(new CryptoCorpusSample(
                "stm32h7-pos-cryp-rng",
                "STM32H7 ARM Cortex-M7 Hardware RNG & CRYP Engine",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.STM32_H7,
                CryptoIsa.ARM_THUMB,
                "Arm GNU GCC 12.3.1 -O2",
                stm32h7Payload.toByteArray(),
                0x08003000L,
                List.of("HAL_RNG_GenerateRandomNumber", "aes_rcon"),
                List.of(
                        HardwareMemoryAccess.write(0x08003000L, 0x50060800L, 4L),   // RNG CR enable
                        HardwareMemoryAccess.write(0x08003010L, 0x50060000L, 0x10L)  // CRYP CR AES-ECB
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.TRNG, CryptoAlgorithm.AES_128),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.CONSTANT_TABLE,
                        CryptoDetectorType.HARDWARE_PERIPHERAL, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "STM32H7 hardware RNG and CRYP peripheral writes with HAL signature and AES Rcon table"
        ));

        // 8. STM32L4 ARM Cortex-M4 AES Peripheral & TinyCrypt
        ByteArrayOutputStream stm32l4Payload = new ByteArrayOutputStream();
        stm32l4Payload.writeBytes(hex.parseHex("b51011461a462346")); // tc_aes_encrypt
        stm32l4Payload.writeBytes(aesInvSbox64);
        list.add(new CryptoCorpusSample(
                "stm32l4-pos-tinycrypt-aes",
                "STM32L4 ARM Cortex-M4 AES Engine & TinyCrypt Wrapper",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.STM32_L4,
                CryptoIsa.ARM_THUMB,
                "Arm GNU GCC 12.3.1 -Os",
                stm32l4Payload.toByteArray(),
                0x08004000L,
                List.of("tc_aes_encrypt"),
                List.of(
                        HardwareMemoryAccess.write(0x08004000L, 0x50060000L, 1L) // AES CR enable
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.AES_128),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.CONSTANT_TABLE,
                        CryptoDetectorType.HARDWARE_PERIPHERAL, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "STM32L4 hardware AES accelerator write, TinyCrypt signature, and inverse S-box table"
        ));

        // 9. STM32WB ARM Cortex-M4 Dual-Core Crypto Mailbox & PKA
        ByteArrayOutputStream stm32wbPayload = new ByteArrayOutputStream();
        stm32wbPayload.writeBytes(hex.parseHex("2de9f04f85b00090")); // mbedtls_aes_crypt_ecb
        stm32wbPayload.writeBytes(key128B);
        list.add(new CryptoCorpusSample(
                "stm32wb-pos-dualcore-crypto-mailbox",
                "STM32WB ARM Cortex-M4 Dual-Core IPCC Key Mailbox & PKA",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.STM32_WB,
                CryptoIsa.ARM_THUMB,
                "Arm GNU GCC 12.3.1 -O2",
                stm32wbPayload.toByteArray(),
                0x08005000L,
                List.of("mbedtls_aes_crypt_ecb"),
                List.of(
                        HardwareMemoryAccess.write(0x08005000L, 0x58002000L, 1L) // PKA CR enable
                ),
                List.of(),
                List.of(new CrossProgramCryptoReference(
                        "CPU1_to_CPU2_KeyMailbox", "CPU1", "CPU2",
                        0x20030000L, 256, "KEY_BLOB_HANDOFF", true)),
                Set.of(CryptoAlgorithm.AES_128, CryptoAlgorithm.ECDSA, CryptoAlgorithm.GENERIC_KEY,
                        CryptoAlgorithm.EFUSE_KEY_LADDER),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.HARDWARE_PERIPHERAL,
                        CryptoDetectorType.KEY_MATERIAL, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "STM32WB dual-core IPCC shared memory key handoff reference, PKA trigger, and mbedTLS signature"
        ));

        // 10. RP2040 ARM Cortex-M0+ ROM Crypto, ATECC608A Secure Element & ChaCha20
        ByteArrayOutputStream rp2040Payload = new ByteArrayOutputStream();
        rp2040Payload.writeBytes(hex.parseHex("2de9f04f04460d46")); // Monocypher crypto_chacha20_djb
        rp2040Payload.writeBytes(hex.parseHex("4408040a40420004")); // ChaCha quarter-round inlined idiom
        rp2040Payload.writeBytes("expand 32-byte k".getBytes(StandardCharsets.US_ASCII));
        list.add(new CryptoCorpusSample(
                "rp2040-pos-rom-atecc608a-chacha",
                "RP2040 ARM Cortex-M0+ ROM Lookup, ATECC608A Bus, & ChaCha20",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.RP2040,
                CryptoIsa.ARM_THUMB,
                "Arm GNU GCC 12.3.1 -O2",
                rp2040Payload.toByteArray(),
                0x10000000L,
                List.of("crypto_chacha20_djb", "chacha20_init"),
                List.of(
                        HardwareMemoryAccess.write(0x10000300L, 0x40058000L, 0x60L) // I2C write to ATECC608A
                ),
                List.of(new HardwareCallSite(
                        0x10000200L, 0x00000010L, "rom_table_lookup",
                        List.of((long) ('R' | ('E' << 8))))), // Flash range erase / crypto routine
                List.of(),
                Set.of(CryptoAlgorithm.CHACHA20, CryptoAlgorithm.FLASH_ENCRYPTION,
                        CryptoAlgorithm.SECURE_ELEMENT),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.CONSTANT_TABLE,
                        CryptoDetectorType.VENDOR_ROM, CryptoDetectorType.HARDWARE_PERIPHERAL,
                        CryptoDetectorType.FUSED_PIPELINE),
                null,
                "RP2040 bootrom crypto routine lookup ('RE'), ATECC608A I2C address, and ChaCha20 signature/idiom"
        ));

        // 11. RP2350 ARM Cortex-M33 Hardware SHA-256 Accelerator
        ByteArrayOutputStream rp2350ArmPayload = new ByteArrayOutputStream();
        rp2350ArmPayload.writeBytes(hex.parseHex("b510490321006009")); // rp2350_sha256_hw_digest
        rp2350ArmPayload.writeBytes(hex.parseHex("b500490220006008")); // pico_sha256_start
        rp2350ArmPayload.writeBytes(sha256K);
        list.add(new CryptoCorpusSample(
                "rp2350-pos-arm-hw-sha256",
                "RP2350 ARM Cortex-M33 Hardware SHA-256 Accelerator & Pico SDK",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.RP2350,
                CryptoIsa.ARM_THUMB,
                "Arm GNU GCC 12.3.1 -O2",
                rp2350ArmPayload.toByteArray(),
                0x10001000L,
                List.of("rp2350_sha256_hw_digest", "pico_sha256_start"),
                List.of(
                        HardwareMemoryAccess.write(0x10001000L, 0x400d0000L, 1L) // SHA-256 trigger
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.SHA256),
                Set.of(CryptoDetectorType.LIBRARY_SIGNATURE, CryptoDetectorType.CONSTANT_TABLE,
                        CryptoDetectorType.HARDWARE_PERIPHERAL, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "RP2350 ARM hardware SHA-256 peripheral trigger, Pico SDK wrapper signatures, and constants"
        ));

        // 12. RP2350 Hazard3 RISC-V 32 Hardware TRNG & Candidate Key
        ByteArrayOutputStream rp2350RvPayload = new ByteArrayOutputStream();
        rp2350RvPayload.writeBytes(key128B);
        list.add(new CryptoCorpusSample(
                "rp2350-pos-hazard3-trng-key",
                "RP2350 Hazard3 RISC-V 32 Hardware TRNG & Candidate Key Material",
                CryptoCorpusClassification.POSITIVE,
                HardwareCryptoPlatform.RP2350,
                CryptoIsa.RISCV32,
                "RISC-V GCC 12.2.0 -O2",
                rp2350RvPayload.toByteArray(),
                0x10002000L,
                List.of("pico_trng_random"),
                List.of(
                        HardwareMemoryAccess.read(0x10002000L, 0x400d8000L) // TRNG read
                ),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.TRNG, CryptoAlgorithm.GENERIC_KEY),
                Set.of(CryptoDetectorType.HARDWARE_PERIPHERAL, CryptoDetectorType.KEY_MATERIAL,
                        CryptoDetectorType.FUSED_PIPELINE),
                null,
                "RP2350 Hazard3 RISC-V hardware TRNG peripheral read and 128-bit candidate key"
        ));

        // =====================================================================
        // SECTION 2: ADVERSARIAL NEGATIVE CORPORA (AN-003 STRICT DIFFERENTIATION)
        // =====================================================================

        // 13. DSP Trigonometric Sine Lookup Table (256 entries * 2 bytes = 512 bytes)
        list.add(new CryptoCorpusSample(
                "negative-sine-lookup-table",
                "Non-Crypto DSP Trigonometric Sine Lookup Table",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Synthesized DSP Math",
                generateSineTable(),
                0x00010000L,
                List.of("dsp_sin_table"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                null,
                "Mathematical sine lookup table that must never be classified as an S-box or encryption (AN-003)"
        ));

        // 14. Standard IEEE 802.3 CRC-32 Table (256 * 4 = 1024 bytes)
        list.add(new CryptoCorpusSample(
                "negative-crc32-ieee-table",
                "Non-Crypto CRC-32 IEEE 802.3 Lookup Table",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard IEEE 802.3",
                generateCrc32Table(),
                0x00011000L,
                List.of("crc32_table"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.CRC32),
                Set.of(CryptoDetectorType.CONSTANT_TABLE, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "CRC-32 checksum table correctly identified as CRC, must NOT have isEncryption() true (AN-003)"
        ));

        // 15. Standard CCITT CRC-16 Table (256 * 2 = 512 bytes)
        list.add(new CryptoCorpusSample(
                "negative-crc16-ccitt-table",
                "Non-Crypto CRC-16 CCITT Lookup Table",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard CCITT",
                generateCrc16Table(),
                0x00012000L,
                List.of("crc16_table"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.CRC16),
                Set.of(CryptoDetectorType.CONSTANT_TABLE, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "CRC-16 checksum table correctly identified as CRC, must NOT have isEncryption() true (AN-003)"
        ));

        // 16. RFC 4648 Base64 Alphabet Encoding Table (64 bytes)
        list.add(new CryptoCorpusSample(
                "negative-base64-alphabet-table",
                "Non-Crypto RFC 4648 Base64 Encoding Alphabet",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard RFC 4648",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes(StandardCharsets.US_ASCII),
                0x00013000L,
                List.of("base64_charset"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.BASE64),
                Set.of(CryptoDetectorType.CONSTANT_TABLE, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "Base64 encoding alphabet table correctly identified as encoding, must NOT have isEncryption() true"
        ));

        // 17. Hexadecimal ASCII Translation Table (32 bytes)
        list.add(new CryptoCorpusSample(
                "negative-hex-ascii-table",
                "Non-Crypto Hexadecimal ASCII Lookup Table",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard C Library",
                "0123456789ABCDEF0123456789abcdef".getBytes(StandardCharsets.US_ASCII),
                0x00014000L,
                List.of("hex_digits"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                null,
                "Hex translation table that must not be classified as encryption"
        ));

        // 18. Huffman Frequency Distribution Matrix
        list.add(new CryptoCorpusSample(
                "negative-huffman-frequency-matrix",
                "Non-Crypto Huffman Frequency & Tree Weights",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Synthesized Compression Table",
                generateHuffmanWeights(),
                0x00015000L,
                List.of("huffman_tree_freq"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                null,
                "Huffman frequency table that must not be classified as an encryption constant"
        ));

        // 19. C Standard Library Character Classification Matrix (ctype, 256 bytes)
        list.add(new CryptoCorpusSample(
                "negative-character-classification-ctype",
                "Non-Crypto C Standard Library ctype Character Classification Matrix",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard POSIX ctype",
                generateCtypeMatrix(),
                0x00016000L,
                List.of("_ctype_b"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                null,
                "POSIX ctype 256-byte classification matrix that must not be classified as an S-box"
        ));

        // 20. Deflate / zlib Fixed Huffman Distance Table
        list.add(new CryptoCorpusSample(
                "negative-deflate-fixed-tables",
                "Non-Crypto Deflate Fixed Huffman Lookup Table",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard RFC 1951 Deflate",
                hex.parseHex("000001000200030004000500070009000d001100190021003100410061008100"),
                0x00017000L,
                List.of("deflate_fixed_dist"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.DEFLATE_ZLIB),
                Set.of(CryptoDetectorType.CONSTANT_TABLE, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "Deflate fixed distance table correctly identified as compression, must NOT have isEncryption() true"
        ));

        // 21. LZ4 Frame Header & Compressed Token Stream
        list.add(new CryptoCorpusSample(
                "negative-lz4-compressed-stream",
                "Non-Crypto LZ4 Block Header & Compressed Data Stream",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard LZ4 Frame",
                generateLz4Stream(),
                0x00018000L,
                List.of("lz4_decompress"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.LZ4),
                Set.of(CryptoDetectorType.CONSTANT_TABLE, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "LZ4 stream correctly identified as compression, must NOT have isEncryption() true (AN-003)"
        ));

        // 22. Ogg Opus Compressed Audio Packet (High-Entropy Non-Crypto Data)
        list.add(new CryptoCorpusSample(
                "negative-compressed-audio-opus",
                "Non-Crypto Compressed Audio Stream (Ogg Opus)",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard Ogg Opus",
                generateOpusAudioStream(),
                0x00019000L,
                List.of("opus_packet_process"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.HIGH_ENTROPY_BLOCK),
                Set.of(CryptoDetectorType.ENTROPY_ANALYSIS, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "High-entropy audio stream recognized as entropy anomaly, must NOT be labeled encryption (AN-003)"
        ));

        // 23. JPEG JFIF Entropy-Coded Image Stream (High-Entropy Non-Crypto Data)
        list.add(new CryptoCorpusSample(
                "negative-compressed-image-jpeg",
                "Non-Crypto Compressed Image Stream (JPEG JFIF)",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard JPEG JFIF",
                generateJpegStream(),
                0x0001a000L,
                List.of("jpeg_decode_scan"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(CryptoAlgorithm.HIGH_ENTROPY_BLOCK),
                Set.of(CryptoDetectorType.ENTROPY_ANALYSIS, CryptoDetectorType.FUSED_PIPELINE),
                null,
                "High-entropy JPEG image stream recognized as entropy anomaly, must NOT be labeled encryption"
        ));

        // 24. Procedural Perlin Noise Permutation Table (256 bytes)
        list.add(new CryptoCorpusSample(
                "negative-procedural-perlin-noise",
                "Non-Crypto Procedural Perlin Noise Permutation Table",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Standard Graphics Shader",
                generatePerlinTable(),
                0x0001b000L,
                List.of("perlin_p_table"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                null,
                "Perlin noise permutation table for procedural textures that must not be classified as encryption"
        ));

        // 25. ARM Thumb Switch-Case Jump Table (32 function pointers)
        list.add(new CryptoCorpusSample(
                "negative-arm-thumb-jump-table",
                "Non-Crypto ARM Thumb Switch-Case Dispatch Jump Table",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.ARM_THUMB,
                "Arm GNU GCC 12.3.1 -O2",
                generateArmJumpTable(),
                0x08008000L,
                List.of("cmd_dispatch_table"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                null,
                "ARM Thumb jump table mimicking constant sequences, verifying zero false cryptographic attribution"
        ));

        // 26. RISC-V Polynomial Sensor Calibration Constants
        list.add(new CryptoCorpusSample(
                "negative-riscv-dense-constants",
                "Non-Crypto RISC-V Dense Sensor Calibration Coefficients",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.RISCV32,
                "RISC-V GCC 12.2.0 -O2",
                generateSensorCalibrationTable(),
                0x20010000L,
                List.of("sensor_calib_coeffs"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                null,
                "Sensor polynomial calibration floating-point constants that must not be labeled encryption"
        ));

        // 27. Xtensa Literal Pool with Non-Crypto MMIO Addresses (GPIO, UART, SPI)
        list.add(new CryptoCorpusSample(
                "negative-xtensa-literal-pool",
                "Non-Crypto Xtensa L32R Literal Pool Containing Peripheral Addresses",
                CryptoCorpusClassification.NEGATIVE_ADVERSARIAL,
                HardwareCryptoPlatform.ESP32,
                CryptoIsa.XTENSA,
                "Xtensa-ESP-ELF GCC 12.2.0 -O2",
                generateXtensaLiteralPool(),
                0x400d0000L,
                List.of("uart_write_char"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                null,
                "Xtensa literal pool with non-crypto UART/GPIO MMIO addresses, verifying zero false leads"
        ));

        // =====================================================================
        // SECTION 3: EXPLICIT UNSUPPORTED CASES & LIMITATIONS (AN-012, AN-015)
        // =====================================================================

        // 28. ESP32 Custom Vectorized SIMD ChaCha20 Implementation
        UnsupportedCase ucChaCha = new UnsupportedCase(
                "unsupported-esp32-custom-vectorized-chacha20",
                "Espressif ESP32",
                "Xtensa LX6 TIE SIMD Assembly",
                CryptoAlgorithm.CHACHA20,
                UnsupportedReason.VECTORIZED_SIMD_WITHOUT_STANDARD_PROLOGUE,
                "Hand-tuned Xtensa TIE SIMD assembly for ChaCha20 quarter-round without standard calling prologue",
                "Planned for T067+ via dedicated Xtensa TIE instruction sequence analyzer"
        );
        list.add(new CryptoCorpusSample(
                ucChaCha.sampleId(),
                "Unsupported: ESP32 Custom Vectorized SIMD ChaCha20",
                CryptoCorpusClassification.UNSUPPORTED_VARIANT,
                HardwareCryptoPlatform.ESP32,
                CryptoIsa.XTENSA,
                "Xtensa TIE SIMD Assembly",
                hex.parseHex("00112233445566778899aabbccddeeff"),
                0x400e0000L,
                List.of("tie_chacha20_simd"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                ucChaCha,
                "Vectorized Xtensa ChaCha20 lacking standard prologue, explicitly tracked as unsupported"
        ));

        // 29. STM32 Proprietary Secure Enclave Interface (OP-TEE SMC)
        UnsupportedCase ucEnclave = new UnsupportedCase(
                "unsupported-stm32-proprietary-secure-enclave",
                "STMicroelectronics STM32MP",
                "ARM Cortex-A SMC TrustZone",
                CryptoAlgorithm.SECURE_ELEMENT,
                UnsupportedReason.PROPRIETARY_SECURE_ENCLAVE,
                "Proprietary OP-TEE TrustZone SMC interface with undocumented OEM service UUIDs",
                "Requires OEM interface specification or vendor symbol pack"
        );
        list.add(new CryptoCorpusSample(
                ucEnclave.sampleId(),
                "Unsupported: STM32 Proprietary Secure Enclave via SMC",
                CryptoCorpusClassification.UNSUPPORTED_VARIANT,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.ARM_THUMB,
                "ARM SMC TrustZone",
                hex.parseHex("03000000700000000000000000000000"),
                0x08010000L,
                List.of("smc_enclave_call"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                ucEnclave,
                "Proprietary OEM secure enclave interface explicitly recorded as unsupported"
        ));

        // 30. RP2040 Bit-Banged Software Crypto in PIO State Machine
        UnsupportedCase ucPio = new UnsupportedCase(
                "unsupported-rp2040-bitbang-soft-crypto",
                "Raspberry Pi RP2040",
                "PIO State Machine Assembly",
                CryptoAlgorithm.AES_128,
                UnsupportedReason.COPROCESSOR_ISOLATED_FIRMWARE,
                "Software bit-banged AES pipeline running inside RP2040 PIO state machines",
                "Requires dedicated PIO instruction sequence analyzer"
        );
        list.add(new CryptoCorpusSample(
                ucPio.sampleId(),
                "Unsupported: RP2040 Bit-Banged AES in PIO State Machine",
                CryptoCorpusClassification.UNSUPPORTED_VARIANT,
                HardwareCryptoPlatform.RP2040,
                CryptoIsa.GENERIC,
                "RP2040 PIO Microcode",
                hex.parseHex("e001e002e003e004a022a044a066a088"),
                0x50200000L,
                List.of("pio_aes_program"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                ucPio,
                "Bit-banged AES running on RP2040 PIO microengine without CPU instructions, recorded as unsupported"
        ));

        // 31. Bitsliced Algebraic AES Without S-Box Tables
        UnsupportedCase ucBitslice = new UnsupportedCase(
                "unsupported-inlined-aes-without-sbox",
                "Generic Silicon",
                "Bitsliced Boolean Logic -O3",
                CryptoAlgorithm.AES_128,
                UnsupportedReason.CUSTOM_INLINED_WITHOUT_CONSTANTS,
                "Bitsliced AES-128 implementation using boolean logic with zero S-box tables or static constants",
                "Requires bounded AST dataflow graph isomorphism analysis"
        );
        list.add(new CryptoCorpusSample(
                ucBitslice.sampleId(),
                "Unsupported: Bitsliced Algebraic AES Without S-Box Tables",
                CryptoCorpusClassification.UNSUPPORTED_VARIANT,
                HardwareCryptoPlatform.GENERIC,
                CryptoIsa.GENERIC,
                "Clang 16.0 -O3 Bitsliced",
                hex.parseHex("4142434445464748494a4b4c4d4e4f50"),
                0x00020000L,
                List.of("aes_bitsliced_round"),
                List.of(),
                List.of(),
                List.of(),
                Set.of(),
                Set.of(),
                ucBitslice,
                "Bitsliced AES without S-box tables, explicitly tracked as unsupported"
        ));

        return new CryptoCorpus(list);
    }

    private static byte[] generateSineTable() {
        byte[] table = new byte[512];
        for (int i = 0; i < 256; i++) {
            double angle = (2.0 * Math.PI * i) / 256.0;
            short val = (short) (Math.sin(angle) * 32767.0);
            table[i * 2] = (byte) (val & 0xFF);
            table[i * 2 + 1] = (byte) ((val >> 8) & 0xFF);
        }
        return table;
    }

    private static byte[] generateCrc32Table() {
        byte[] table = new byte[1024];
        for (int i = 0; i < 256; i++) {
            int crc = i;
            for (int j = 0; j < 8; j++) {
                if ((crc & 1) != 0) {
                    crc = (crc >>> 1) ^ 0xEDB88320;
                } else {
                    crc >>>= 1;
                }
            }
            table[i * 4] = (byte) (crc & 0xFF);
            table[i * 4 + 1] = (byte) ((crc >> 8) & 0xFF);
            table[i * 4 + 2] = (byte) ((crc >> 16) & 0xFF);
            table[i * 4 + 3] = (byte) ((crc >> 24) & 0xFF);
        }
        return table;
    }

    private static byte[] generateCrc16Table() {
        byte[] table = new byte[512];
        for (int i = 0; i < 256; i++) {
            int crc = i << 8;
            for (int j = 0; j < 8; j++) {
                if ((crc & 0x8000) != 0) {
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF;
                } else {
                    crc = (crc << 1) & 0xFFFF;
                }
            }
            table[i * 2] = (byte) (crc & 0xFF);
            table[i * 2 + 1] = (byte) ((crc >> 8) & 0xFF);
        }
        return table;
    }

    private static byte[] generateHuffmanWeights() {
        byte[] weights = new byte[256];
        for (int i = 0; i < 256; i++) {
            weights[i] = (byte) ((i * 3 + 7) % 19);
        }
        return weights;
    }

    private static byte[] generateCtypeMatrix() {
        byte[] ctype = new byte[256];
        for (int i = 0; i < 256; i++) {
            int mask = 0;
            if (Character.isUpperCase(i)) {
                mask |= 0x01;
            }
            if (Character.isLowerCase(i)) {
                mask |= 0x02;
            }
            if (Character.isDigit(i)) {
                mask |= 0x04;
            }
            if (Character.isWhitespace(i)) {
                mask |= 0x08;
            }
            ctype[i] = (byte) mask;
        }
        return ctype;
    }

    private static byte[] generateLz4Stream() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {(byte) 0x04, (byte) 0x22, (byte) 0x4D, (byte) 0x18}); // LZ4 Magic
        out.writeBytes(new byte[] {(byte) 0x64, (byte) 0x70, (byte) 0xB7}); // Frame descriptor
        byte[] tokens = new byte[128];
        for (int i = 0; i < tokens.length; i++) {
            tokens[i] = (byte) ((i * 17) & 0xFF);
        }
        out.writeBytes(tokens);
        return out.toByteArray();
    }

    private static byte[] generateOpusAudioStream() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes("OggS".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(new byte[] {0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 19});
        out.writeBytes("OpusHead".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(new byte[] {1, 2, 56, 1, 0, 0, 0, 0, 0});
        // High entropy deterministic pseudo-random compressed audio stream (1024 bytes)
        Random rng = new Random(0x1337BEEFL);
        byte[] entropy = new byte[1024];
        rng.nextBytes(entropy);
        out.writeBytes(entropy);
        return out.toByteArray();
    }

    private static byte[] generateJpegStream() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0}); // SOI, APP0
        out.writeBytes(new byte[] {0, 16}); // Length
        out.writeBytes("JFIF".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(new byte[] {0, 1, 1, 0, 0, 1, 0, 1, 0, 0});
        // High entropy deterministic pseudo-random DCT image payload (1024 bytes)
        Random rng = new Random(0xCAFEBABEL);
        byte[] entropy = new byte[1024];
        rng.nextBytes(entropy);
        out.writeBytes(entropy);
        return out.toByteArray();
    }

    private static byte[] generatePerlinTable() {
        byte[] p = new byte[256];
        for (int i = 0; i < 256; i++) {
            p[i] = (byte) ((i * 151 + 7) & 0xFF);
        }
        return p;
    }

    private static byte[] generateArmJumpTable() {
        byte[] table = new byte[128];
        for (int i = 0; i < 32; i++) {
            int target = 0x08001001 + (i * 16); // Thumb bit set
            table[i * 4] = (byte) (target & 0xFF);
            table[i * 4 + 1] = (byte) ((target >> 8) & 0xFF);
            table[i * 4 + 2] = (byte) ((target >> 16) & 0xFF);
            table[i * 4 + 3] = (byte) ((target >> 24) & 0xFF);
        }
        return table;
    }

    private static byte[] generateSensorCalibrationTable() {
        byte[] table = new byte[128];
        for (int i = 0; i < 32; i++) {
            float coeff = 1.05f + (i * 0.03125f);
            int bits = Float.floatToIntBits(coeff);
            table[i * 4] = (byte) (bits & 0xFF);
            table[i * 4 + 1] = (byte) ((bits >> 8) & 0xFF);
            table[i * 4 + 2] = (byte) ((bits >> 16) & 0xFF);
            table[i * 4 + 3] = (byte) ((bits >> 24) & 0xFF);
        }
        return table;
    }

    private static byte[] generateXtensaLiteralPool() {
        int[] literals = new int[] {
            0x3ff40000, // UART0 base
            0x3ff44000, // GPIO base
            0x3ff42000, // SPI1 base
            0x3ff43000, // SPI2 base
            0x3ff48000, // I2C0 base
            0x3ff5f000, // TIMERG0 base
            115200,     // Baud rate constant
            0x000000ff  // Mask constant
        };
        byte[] pool = new byte[literals.length * 4];
        for (int i = 0; i < literals.length; i++) {
            int lit = literals[i];
            pool[i * 4] = (byte) (lit & 0xFF);
            pool[i * 4 + 1] = (byte) ((lit >> 8) & 0xFF);
            pool[i * 4 + 2] = (byte) ((lit >> 16) & 0xFF);
            pool[i * 4 + 3] = (byte) ((lit >> 24) & 0xFF);
        }
        return pool;
    }
}
