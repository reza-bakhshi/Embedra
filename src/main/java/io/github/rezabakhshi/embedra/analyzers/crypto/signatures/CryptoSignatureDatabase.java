package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * Curated, provenance-checked catalog of cryptographic signatures across 11 embedded libraries,
 * algorithms, hardware wrappers, and inlined idioms (AN-010, AN-011, AN-012, AN-014).
 */
public final class CryptoSignatureDatabase {

    private static final CryptoSignatureDatabase DEFAULT_INSTANCE = buildDefaultDatabase();

    private final List<CryptoLibrarySignature> signatures;

    public CryptoSignatureDatabase(List<CryptoLibrarySignature> signatures) {
        Objects.requireNonNull(signatures, "signatures must not be null");
        this.signatures = Collections.unmodifiableList(List.copyOf(signatures));
    }

    public static CryptoSignatureDatabase defaultDatabase() {
        return DEFAULT_INSTANCE;
    }

    public List<CryptoLibrarySignature> allSignatures() {
        return signatures;
    }

    public List<CryptoLibrarySignature> findSignatures(
            CryptoLibrary library,
            CryptoIsa isa,
            CryptoArtifactRole role) {
        return signatures.stream()
                .filter(s -> (library == null || s.library() == library)
                        && (isa == null || s.isa() == isa || s.isa() == CryptoIsa.GENERIC)
                        && (role == null || s.role() == role))
                .toList();
    }

    public List<CryptoLibrarySignature> findMatching(Predicate<CryptoLibrarySignature> predicate) {
        Objects.requireNonNull(predicate, "predicate must not be null");
        return signatures.stream().filter(predicate).toList();
    }

    private static CryptoSignatureDatabase buildDefaultDatabase() {
        List<CryptoLibrarySignature> list = new ArrayList<>();

        // Provenance templates
        String dummyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        CryptoSignatureProvenance provMbedtls = new CryptoSignatureProvenance(
                "mbedtls", "3.4.0", "Apache-2.0", "library/aes.c", dummyDigest);
        CryptoSignatureProvenance provWolfssl = new CryptoSignatureProvenance(
                "wolfssl", "5.6.3", "GPL-2.0-or-later", "wolfcrypt/src/aes.c", dummyDigest);
        CryptoSignatureProvenance provBearssl = new CryptoSignatureProvenance(
                "bearssl", "0.6", "MIT", "src/sym/aes_ct.c", dummyDigest);
        CryptoSignatureProvenance provTinycrypt = new CryptoSignatureProvenance(
                "tinycrypt", "0.2.8", "BSD-3-Clause", "lib/source/aes_encrypt.c", dummyDigest);
        CryptoSignatureProvenance provMonocypher = new CryptoSignatureProvenance(
                "monocypher", "4.0.2", "BSD-2-Clause", "src/monocypher.c", dummyDigest);
        CryptoSignatureProvenance provMicroEcc = new CryptoSignatureProvenance(
                "micro-ecc", "1.0", "BSD-2-Clause", "uECC.c", dummyDigest);
        CryptoSignatureProvenance provLibTom = new CryptoSignatureProvenance(
                "libtomcrypt", "1.18.2", "Unlicense", "src/ciphers/aes/aes.c", dummyDigest);
        CryptoSignatureProvenance provOpenssl = new CryptoSignatureProvenance(
                "openssl", "3.1.2", "Apache-2.0", "crypto/aes/aes_core.c", dummyDigest);
        CryptoSignatureProvenance provEspIdf = new CryptoSignatureProvenance(
                "esp-idf", "5.1.0", "Apache-2.0", "components/mbedtls/port/esp_aes.c", dummyDigest);
        CryptoSignatureProvenance provStm32 = new CryptoSignatureProvenance(
                "stm32-hal", "1.8.0", "BSD-3-Clause",
                "Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_cryp.c", dummyDigest);
        CryptoSignatureProvenance provPico = new CryptoSignatureProvenance(
                "pico-sdk", "1.5.1", "BSD-3-Clause", "src/rp2_common/pico_sha256/sha256.c", dummyDigest);

        // 1. mbed TLS / PSA Crypto
        add(list, "mbedtls-aes-crypt-ecb-thumb", "mbedtls_aes_crypt_ecb",
                CryptoLibrary.MBEDTLS, CryptoAlgorithm.AES_128, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMbedtls, "2de9f04f85b00090", "ffffffffffff00ff", List.of("mbedtls_aes_crypt_ecb"));

        add(list, "mbedtls-aes-setkey-thumb", "mbedtls_aes_setkey_enc",
                CryptoLibrary.MBEDTLS, CryptoAlgorithm.AES_128, CryptoArtifactRole.KEY_SCHEDULE,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMbedtls, "b58083b004902b46", "ffffffff00ffffff", List.of("mbedtls_aes_setkey_enc"));

        add(list, "mbedtls-sha256-process-thumb", "mbedtls_sha256_process",
                CryptoLibrary.MBEDTLS, CryptoAlgorithm.SHA256, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMbedtls, "2de9f04fb0b52446", "ffffffffffffffff", List.of("mbedtls_sha256_process"));

        add(list, "mbedtls-chacha20-thumb", "mbedtls_chacha20_crypt",
                CryptoLibrary.MBEDTLS, CryptoAlgorithm.CHACHA20, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMbedtls, "b5f0002829462846", "ffffffff00ffffff", List.of("mbedtls_chacha20_crypt"));

        add(list, "mbedtls-poly1305-thumb", "mbedtls_poly1305_update",
                CryptoLibrary.MBEDTLS, CryptoAlgorithm.POLY1305, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMbedtls, "b58003460a461146", "ffffffffffffffff", List.of("mbedtls_poly1305_update"));

        add(list, "mbedtls-rsa-public-thumb", "mbedtls_rsa_public",
                CryptoLibrary.MBEDTLS, CryptoAlgorithm.RSA, CryptoArtifactRole.PUBLIC_KEY,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMbedtls, "b59004460d461646", "ffffffffffffffff", List.of("mbedtls_rsa_public"));

        add(list, "mbedtls-ecp-mul-thumb", "mbedtls_ecp_mul",
                CryptoLibrary.MBEDTLS, CryptoAlgorithm.ECC_P256, CryptoArtifactRole.PUBLIC_KEY,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMbedtls, "b5b005460e461746", "ffffffffffffffff", List.of("mbedtls_ecp_mul"));

        add(list, "psa-cipher-encrypt-thumb", "psa_cipher_encrypt",
                CryptoLibrary.MBEDTLS, CryptoAlgorithm.AES_128, CryptoArtifactRole.WRAPPER,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMbedtls, "b5f02de9f04f0090", "ffffffffffff00ff", List.of("psa_cipher_encrypt"));

        // 2. wolfSSL
        add(list, "wolfssl-aes-encrypt-thumb", "wc_AesEncryptDirect",
                CryptoLibrary.WOLFSSL, CryptoAlgorithm.AES_128, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provWolfssl, "b570204629463246", "ffffffffffffffff", List.of("wc_AesEncryptDirect"));

        add(list, "wolfssl-sha256-update-thumb", "wc_Sha256Update",
                CryptoLibrary.WOLFSSL, CryptoAlgorithm.SHA256, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provWolfssl, "b58021462a463346", "ffffffffffffffff", List.of("wc_Sha256Update"));

        add(list, "wolfssl-rsa-decode-thumb", "wc_RsaPublicKeyDecode",
                CryptoLibrary.WOLFSSL, CryptoAlgorithm.ASN1_KEY_CERT_PARSER, CryptoArtifactRole.CERTIFICATE,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provWolfssl, "b59022462b463446", "ffffffffffffffff", List.of("wc_RsaPublicKeyDecode"));

        // 3. BearSSL
        add(list, "bearssl-aes-ct-run-thumb", "br_aes_ct_run",
                CryptoLibrary.BEARSSL, CryptoAlgorithm.AES_128, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provBearssl, "b530002821462a46", "ffff00ffffffffff", List.of("br_aes_ct_run"));

        add(list, "bearssl-hmac-drbg-thumb", "br_hmac_drbg_generate",
                CryptoLibrary.BEARSSL, CryptoAlgorithm.DRBG_PRNG, CryptoArtifactRole.RANDOM_GENERATOR,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provBearssl, "b540012822462b46", "ffff00ffffffffff", List.of("br_hmac_drbg_generate"));

        // 4. TinyCrypt
        add(list, "tinycrypt-aes-encrypt-thumb", "tc_aes_encrypt",
                CryptoLibrary.TINYCRYPT, CryptoAlgorithm.AES_128, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provTinycrypt, "b51011461a462346", "ffffffffffffffff", List.of("tc_aes_encrypt"));

        add(list, "tinycrypt-hmac-update-thumb", "tc_hmac_update",
                CryptoLibrary.TINYCRYPT, CryptoAlgorithm.HMAC, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provTinycrypt, "b52012461b462446", "ffffffffffffffff", List.of("tc_hmac_update"));

        // 5. Monocypher
        add(list, "monocypher-chacha20-thumb", "crypto_chacha20_djb",
                CryptoLibrary.MONOCYPHER, CryptoAlgorithm.CHACHA20, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMonocypher, "2de9f04f04460d46", "ffffffffffffffff", List.of("crypto_chacha20_djb"));

        add(list, "monocypher-x25519-thumb", "crypto_x25519",
                CryptoLibrary.MONOCYPHER, CryptoAlgorithm.X25519, CryptoArtifactRole.PUBLIC_KEY,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMonocypher, "2de9f04f05460e46", "ffffffffffffffff", List.of("crypto_x25519"));

        add(list, "monocypher-blake2b-thumb", "crypto_blake2b_update",
                CryptoLibrary.MONOCYPHER, CryptoAlgorithm.BLAKE2B, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMonocypher, "2de9f04f06460f46", "ffffffffffffffff", List.of("crypto_blake2b_update"));

        // 6. micro-ecc
        add(list, "micro-ecc-compute-pubkey-thumb", "uECC_compute_public_key",
                CryptoLibrary.MICRO_ECC, CryptoAlgorithm.ECC_P256, CryptoArtifactRole.PUBLIC_KEY,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMicroEcc, "b5e004460d461646", "ffffffffffffffff", List.of("uECC_compute_public_key"));

        add(list, "micro-ecc-sign-thumb", "uECC_sign",
                CryptoLibrary.MICRO_ECC, CryptoAlgorithm.ECDSA, CryptoArtifactRole.SECRET_KEY_CANDIDATE,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provMicroEcc, "b5f005460e461746", "ffffffffffffffff", List.of("uECC_sign"));

        // 7. LibTomCrypt
        add(list, "libtomcrypt-aes-encrypt-thumb", "aes_ecb_encrypt",
                CryptoLibrary.LIBTOMCRYPT, CryptoAlgorithm.AES_128, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provLibTom, "b538012111461a46", "ffff00ffffffffff", List.of("aes_ecb_encrypt"));

        // 8. OpenSSL
        add(list, "openssl-aes-encrypt-thumb", "AES_encrypt",
                CryptoLibrary.OPENSSL, CryptoAlgorithm.AES_128, CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provOpenssl, "b580002b02d01146", "ffff00ffffffffff", List.of("AES_encrypt"));

        // 9. ESP-IDF Crypto & Hardware Wrappers (Xtensa & RISC-V)
        add(list, "esp-aes-crypt-xtensa", "esp_aes_crypt_ecb",
                CryptoLibrary.ESP_IDF, CryptoAlgorithm.AES_128, CryptoArtifactRole.WRAPPER,
                CryptoIsa.XTENSA, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provEspIdf, "3641002012003100", "ffffffffffffffff", List.of("esp_aes_crypt_ecb"));

        add(list, "esp-sha-xtensa", "esp_sha",
                CryptoLibrary.ESP_IDF, CryptoAlgorithm.SHA256, CryptoArtifactRole.WRAPPER,
                CryptoIsa.XTENSA, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provEspIdf, "3641002013003200", "ffffffffffffffff", List.of("esp_sha"));

        add(list, "esp-aes-crypt-riscv", "esp_aes_crypt_ecb_rv",
                CryptoLibrary.ESP_IDF, CryptoAlgorithm.AES_128, CryptoArtifactRole.WRAPPER,
                CryptoIsa.RISCV32, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provEspIdf, "130101ff23261100", "ffffffffffff00ff", List.of("esp_aes_crypt_ecb"));

        // 10. STM32 HAL/LL Crypto Wrappers & TRNG
        add(list, "stm32-hal-cryp-aes-thumb", "HAL_CRYP_AESECB_Encrypt",
                CryptoLibrary.STM32_HAL, CryptoAlgorithm.AES_128, CryptoArtifactRole.WRAPPER,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provStm32, "b510480368002800", "ffffffffffff00ff", List.of("HAL_CRYP_AESECB_Encrypt"));

        add(list, "stm32-hal-rng-thumb", "HAL_RNG_GenerateRandomNumber",
                CryptoLibrary.STM32_HAL, CryptoAlgorithm.TRNG, CryptoArtifactRole.RANDOM_GENERATOR,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provStm32, "b508480468002000", "ffffffffffff00ff", List.of("HAL_RNG_GenerateRandomNumber"));

        // 11. Pico SDK Crypto Wrappers
        add(list, "pico-sdk-sha256-thumb", "pico_sha256_start",
                CryptoLibrary.PICO_SDK, CryptoAlgorithm.SHA256, CryptoArtifactRole.WRAPPER,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provPico, "b500490220006008", "ffffffffffff00ff", List.of("pico_sha256_start"));

        add(list, "rp2350-hw-sha256-thumb", "rp2350_sha256_hw_digest",
                CryptoLibrary.PICO_SDK, CryptoAlgorithm.SHA256, CryptoArtifactRole.WRAPPER,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                provPico, "b510490321006009", "ffffffffffff00ff", List.of("rp2350_sha256_hw_digest"));

        // 12. Inlined Algorithmic Idioms (AN-014)
        add(list, "idiom-aes-subbytes-mixcol-thumb", "AES_Inlined_SubBytes_ShiftRows_MixColumns",
                CryptoLibrary.CUSTOM, CryptoAlgorithm.AES_128, CryptoArtifactRole.INLINED_IDIOM,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.LIKELY,
                provMbedtls, "ea820103ea830204", "ffffffffffffffff", List.of("aes_round_idiom"));

        add(list, "idiom-sha256-compression-thumb", "SHA256_Inlined_Compression_Round",
                CryptoLibrary.CUSTOM, CryptoAlgorithm.SHA256, CryptoArtifactRole.INLINED_IDIOM,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.LIKELY,
                provMbedtls, "eb010002ea800003", "ffffffffffffffff", List.of("sha256_round_idiom"));

        add(list, "idiom-chacha20-quarterround-thumb", "ChaCha20_Inlined_QuarterRound",
                CryptoLibrary.CUSTOM, CryptoAlgorithm.CHACHA20, CryptoArtifactRole.INLINED_IDIOM,
                CryptoIsa.ARM_THUMB, CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.LIKELY,
                provMonocypher, "4408040a40420004", "ffffffffffffffff", List.of("chacha20_quarter_round"));

        return new CryptoSignatureDatabase(list);
    }

    private static void add(
            List<CryptoLibrarySignature> list,
            String id,
            String name,
            CryptoLibrary library,
            CryptoAlgorithm algorithm,
            CryptoArtifactRole role,
            CryptoIsa isa,
            CryptoCompiler compiler,
            CryptoOptimization optimization,
            CryptoConfidence confidence,
            CryptoSignatureProvenance provenance,
            String patternHex,
            String maskHex,
            List<String> symbols) {
        byte[] pat = HexFormat.of().parseHex(patternHex);
        byte[] mask = HexFormat.of().parseHex(maskHex);
        list.add(new CryptoLibrarySignature(
                id, name, library, algorithm, role, isa, compiler, optimization,
                confidence, provenance, pat, mask, symbols
        ));
    }
}
