package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CryptoSignatureDatabaseTest {

    @Test
    void defaultDatabaseContainsAllElevenRequiredLibraries() {
        CryptoSignatureDatabase db = CryptoSignatureDatabase.defaultDatabase();
        assertNotNull(db);
        assertFalse(db.allSignatures().isEmpty());

        Set<CryptoLibrary> foundLibraries = new HashSet<>();
        for (CryptoLibrarySignature sig : db.allSignatures()) {
            foundLibraries.add(sig.library());
        }

        // AN-011 required embedded implementations:
        assertTrue(foundLibraries.contains(CryptoLibrary.MBEDTLS), "mbed TLS / PSA Crypto missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.WOLFSSL), "wolfSSL missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.BEARSSL), "BearSSL missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.TINYCRYPT), "TinyCrypt missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.MONOCYPHER), "Monocypher missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.MICRO_ECC), "micro-ecc missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.LIBTOMCRYPT), "LibTomCrypt missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.OPENSSL), "OpenSSL missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.ESP_IDF), "ESP-IDF crypto missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.STM32_HAL), "STM32 HAL/LL crypto missing");
        assertTrue(foundLibraries.contains(CryptoLibrary.PICO_SDK), "Pico SDK crypto missing");
    }

    @Test
    void coversRequiredArtifactRolesAndInlinedVariants() {
        CryptoSignatureDatabase db = CryptoSignatureDatabase.defaultDatabase();

        Set<CryptoArtifactRole> foundRoles = new HashSet<>();
        for (CryptoLibrarySignature sig : db.allSignatures()) {
            foundRoles.add(sig.role());
        }

        // AN-014 distinctions:
        assertTrue(foundRoles.contains(CryptoArtifactRole.ALGORITHM_IMPLEMENTATION),
                "Algorithm implementation missing");
        assertTrue(foundRoles.contains(CryptoArtifactRole.WRAPPER), "Wrapper missing");
        assertTrue(foundRoles.contains(CryptoArtifactRole.INLINED_IDIOM), "Inlined idiom missing");
    }

    @Test
    void coversTargetISAs() {
        CryptoSignatureDatabase db = CryptoSignatureDatabase.defaultDatabase();

        Set<CryptoIsa> foundIsas = new HashSet<>();
        for (CryptoLibrarySignature sig : db.allSignatures()) {
            foundIsas.add(sig.isa());
        }

        assertTrue(foundIsas.contains(CryptoIsa.ARM_THUMB), "ARM Thumb missing");
        assertTrue(foundIsas.contains(CryptoIsa.XTENSA), "Xtensa missing");
        assertTrue(foundIsas.contains(CryptoIsa.RISCV32), "RISC-V 32 missing");
    }

    @Test
    void coversCoreCryptographicAlgorithms() {
        CryptoSignatureDatabase db = CryptoSignatureDatabase.defaultDatabase();

        Set<CryptoAlgorithm> foundAlgos = new HashSet<>();
        for (CryptoLibrarySignature sig : db.allSignatures()) {
            foundAlgos.add(sig.algorithm());
        }

        // AN-012 algorithm requirements:
        assertTrue(foundAlgos.contains(CryptoAlgorithm.AES_128) || foundAlgos.contains(CryptoAlgorithm.AES_256),
                "AES missing");
        assertTrue(foundAlgos.contains(CryptoAlgorithm.SHA256), "SHA-256 missing");
        assertTrue(foundAlgos.contains(CryptoAlgorithm.CHACHA20)
                        || foundAlgos.contains(CryptoAlgorithm.CHACHA20_POLY1305),
                "ChaCha20 missing");
        assertTrue(foundAlgos.contains(CryptoAlgorithm.POLY1305), "Poly1305 missing");
        assertTrue(foundAlgos.contains(CryptoAlgorithm.RSA), "RSA missing");
        assertTrue(foundAlgos.contains(CryptoAlgorithm.ECC_P256) || foundAlgos.contains(CryptoAlgorithm.ECDSA),
                "ECC missing");
        assertTrue(foundAlgos.contains(CryptoAlgorithm.ED25519) || foundAlgos.contains(CryptoAlgorithm.X25519),
                "Ed25519 / X25519 missing");
        assertTrue(foundAlgos.contains(CryptoAlgorithm.BLAKE2B) || foundAlgos.contains(CryptoAlgorithm.BLAKE2S),
                "BLAKE2 missing");
        assertTrue(foundAlgos.contains(CryptoAlgorithm.HMAC), "HMAC missing");
    }

    @Test
    void queryMethodsFilterCorrectly() {
        CryptoSignatureDatabase db = CryptoSignatureDatabase.defaultDatabase();

        List<CryptoLibrarySignature> mbedThumb = db.findSignatures(
                CryptoLibrary.MBEDTLS,
                CryptoIsa.ARM_THUMB,
                CryptoArtifactRole.ALGORITHM_IMPLEMENTATION
        );
        assertFalse(mbedThumb.isEmpty());
        for (CryptoLibrarySignature s : mbedThumb) {
            assertTrue(s.library() == CryptoLibrary.MBEDTLS);
            assertTrue(s.isa() == CryptoIsa.ARM_THUMB);
            assertTrue(s.role() == CryptoArtifactRole.ALGORITHM_IMPLEMENTATION);
        }
    }
}
