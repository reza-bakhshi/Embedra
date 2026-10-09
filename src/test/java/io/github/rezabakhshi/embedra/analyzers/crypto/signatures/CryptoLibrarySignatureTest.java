package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import java.util.List;
import org.junit.jupiter.api.Test;

class CryptoLibrarySignatureTest {

    private static final String VALID_SHA256 =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    private static final CryptoSignatureProvenance PROVENANCE = new CryptoSignatureProvenance(
            "mbedtls",
            "3.4.0",
            "Apache-2.0",
            "library/aes.c",
            VALID_SHA256
    );

    @Test
    void validSignatureConstructsAndMatches() {
        byte[] pattern = new byte[] {
                (byte) 0x2d, (byte) 0xe9, (byte) 0xf0, (byte) 0x4f,
                (byte) 0x85, (byte) 0xb0, (byte) 0x00, (byte) 0x90
        };
        byte[] mask = new byte[] {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0xff
        };

        CryptoLibrarySignature sig = new CryptoLibrarySignature(
                "mbedtls-aes-crypt-ecb-thumb-o2",
                "mbedtls_aes_crypt_ecb",
                CryptoLibrary.MBEDTLS,
                CryptoAlgorithm.AES_128,
                CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB,
                CryptoCompiler.GCC,
                CryptoOptimization.O2,
                CryptoConfidence.CONFIRMED,
                PROVENANCE,
                pattern,
                mask,
                List.of("mbedtls_aes_crypt_ecb")
        );

        assertEquals("mbedtls-aes-crypt-ecb-thumb-o2", sig.id());
        assertEquals("mbedtls_aes_crypt_ecb", sig.name());
        assertEquals(CryptoLibrary.MBEDTLS, sig.library());
        assertEquals(CryptoAlgorithm.AES_128, sig.algorithm());
        assertEquals(CryptoArtifactRole.ALGORITHM_IMPLEMENTATION, sig.role());
        assertEquals(CryptoIsa.ARM_THUMB, sig.isa());
        assertEquals(CryptoCompiler.GCC, sig.compiler());
        assertEquals(CryptoOptimization.O2, sig.optimization());
        assertEquals(CryptoConfidence.CONFIRMED, sig.confidence());
        assertEquals(PROVENANCE, sig.provenance());
        assertArrayEquals(pattern, sig.pattern());
        assertArrayEquals(mask, sig.mask());
        assertEquals(List.of("mbedtls_aes_crypt_ecb"), sig.crossReferenceSymbols());

        // Test matching
        byte[] matchingData = new byte[] {
                (byte) 0x2d, (byte) 0xe9, (byte) 0xf0, (byte) 0x4f,
                (byte) 0x85, (byte) 0xb0, (byte) 0xaa, (byte) 0x90 // 0xaa matches wildcard mask 0x00
        };
        assertTrue(sig.matches(matchingData, 0));

        byte[] nonMatchingData = new byte[] {
                (byte) 0x2d, (byte) 0xe9, (byte) 0xf0, (byte) 0x4f,
                (byte) 0x85, (byte) 0xb0, (byte) 0xaa, (byte) 0x91 // 0x91 != 0x90
        };
        assertFalse(sig.matches(nonMatchingData, 0));
    }

    @Test
    void rejectsInvalidProvenanceDigest() {
        assertThrows(IllegalArgumentException.class, () -> new CryptoSignatureProvenance(
                "mbedtls", "3.4.0", "Apache-2.0", "library/aes.c", "invalid_digest"
        ));
    }

    @Test
    void rejectsShortPatternOrMismatchedMask() {
        byte[] shortPat = new byte[] { 1, 2, 3 };
        byte[] shortMask = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff };

        assertThrows(IllegalArgumentException.class, () -> new CryptoLibrarySignature(
                "id", "name", CryptoLibrary.MBEDTLS, CryptoAlgorithm.AES_128,
                CryptoArtifactRole.ALGORITHM_IMPLEMENTATION, CryptoIsa.ARM_THUMB,
                CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                PROVENANCE, shortPat, shortMask, List.of()
        ));

        byte[] pat8 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] mask9 = new byte[] {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
        };

        assertThrows(IllegalArgumentException.class, () -> new CryptoLibrarySignature(
                "id", "name", CryptoLibrary.MBEDTLS, CryptoAlgorithm.AES_128,
                CryptoArtifactRole.ALGORITHM_IMPLEMENTATION, CryptoIsa.ARM_THUMB,
                CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                PROVENANCE, pat8, mask9, List.of()
        ));
    }

    @Test
    void rejectsInvalidMaskValues() {
        byte[] pat8 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] badMask = new byte[] {
                (byte) 0xff, (byte) 0x7f, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
        };

        assertThrows(IllegalArgumentException.class, () -> new CryptoLibrarySignature(
                "id", "name", CryptoLibrary.MBEDTLS, CryptoAlgorithm.AES_128,
                CryptoArtifactRole.ALGORITHM_IMPLEMENTATION, CryptoIsa.ARM_THUMB,
                CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                PROVENANCE, pat8, badMask, List.of()
        ));
    }

    @Test
    void rejectsInsufficientSignificantBytes() {
        byte[] pat8 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        // Only 3 significant bytes (fewer than 4)
        byte[] sparseMask = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0 };

        assertThrows(IllegalArgumentException.class, () -> new CryptoLibrarySignature(
                "id", "name", CryptoLibrary.MBEDTLS, CryptoAlgorithm.AES_128,
                CryptoArtifactRole.ALGORITHM_IMPLEMENTATION, CryptoIsa.ARM_THUMB,
                CryptoCompiler.GCC, CryptoOptimization.O2, CryptoConfidence.CONFIRMED,
                PROVENANCE, pat8, sparseMask, List.of()
        ));
    }
}
