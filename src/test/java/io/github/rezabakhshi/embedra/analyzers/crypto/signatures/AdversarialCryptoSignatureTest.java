package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class AdversarialCryptoSignatureTest {

    @Test
    void rejectsTruncatedJson() {
        byte[] truncated = "{\"schemaId\":\"urn:embedra:schema:crypto-signature-pack:1\""
                .getBytes(StandardCharsets.UTF_8);
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                CryptoSignaturePackLoader.load(truncated, ParserLimits.defaults(), CancellationToken.none())
        );
        assertEquals(DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID, ex.diagnostic().code());
    }

    @Test
    void rejectsDuplicateKeysInPackJson() {
        String json = """
                {
                  "schemaId": "urn:embedra:schema:crypto-signature-pack:1",
                  "packId": "pack1",
                  "packId": "pack2",
                  "version": "1.0.0",
                  "description": "desc",
                  "integrityDigest": "0000000000000000000000000000000000000000000000000000000000000000",
                  "signatures": []
                }
                """;
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                CryptoSignaturePackLoader.load(
                        json.getBytes(StandardCharsets.UTF_8),
                        ParserLimits.defaults(),
                        CancellationToken.none()
                )
        );
        assertEquals(DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID, ex.diagnostic().code());
    }

    @Test
    void rejectsExcessiveNestingDepth() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            sb.append("{\"a\":");
        }
        sb.append("1");
        for (int i = 0; i < 40; i++) {
            sb.append("}");
        }
        byte[] deeplyNested = sb.toString().getBytes(StandardCharsets.UTF_8);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                CryptoSignaturePackLoader.load(deeplyNested, ParserLimits.defaults(), CancellationToken.none())
        );
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void rejectsOversizedInput() {
        byte[] huge = new byte[100];
        ParserLimits limits = new ParserLimits(50, 50, 50, 50, 10, Duration.ofSeconds(1));

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                CryptoSignaturePackLoader.load(huge, limits, CancellationToken.none())
        );
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void matchesHandlesOutOfBoundsGracefully() {
        CryptoSignatureProvenance prov = new CryptoSignatureProvenance(
                "mbedtls", "3.4.0", "Apache-2.0", "aes.c",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        byte[] pat = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] mask = new byte[] {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
        };

        CryptoLibrarySignature sig = new CryptoLibrarySignature(
                "test-id", "test", CryptoLibrary.MBEDTLS, CryptoAlgorithm.AES_128,
                CryptoArtifactRole.ALGORITHM_IMPLEMENTATION, CryptoIsa.GENERIC,
                CryptoCompiler.ANY, CryptoOptimization.ANY, CryptoConfidence.CONFIRMED,
                prov, pat, mask, List.of()
        );

        assertFalse(sig.matches(null, 0));
        assertFalse(sig.matches(new byte[10], -1));
        assertFalse(sig.matches(new byte[10], 4)); // 4 + 8 > 10 -> out of bounds
        assertFalse(sig.matches(new byte[5], 0));  // 5 < 8 -> out of bounds
    }

    @Test
    void scannerEnforcesExecutionBudget() {
        byte[] bigBuffer = new byte[1024 * 1024]; // 1 MB
        CryptoLibrarySignatureMatcher matcher = new CryptoLibrarySignatureMatcher();
        // Tiny 1-nanosecond budget
        ParserLimits limits = new ParserLimits(10_000_000, 10_000_000, 10_000_000, 10_000, 32, Duration.ofNanos(1));

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                matcher.scan(bigBuffer, 0L, CryptoIsa.ARM_THUMB, limits, CancellationToken.none())
        );
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void secretsAreMaskedInFindings() throws Exception {
        // Test secret masking on SECRET_KEY_CANDIDATE role
        // Monocypher Ed25519 Sign has role SECRET_KEY_CANDIDATE
        CryptoSignatureDatabase db = CryptoSignatureDatabase.defaultDatabase();
        CryptoLibrarySignatureMatcher matcher = new CryptoLibrarySignatureMatcher(db);

        // Pattern for monocypher-ed25519-sign:
        // We can find the signature and scan its exact pattern
        var sigOpt = db.allSignatures().stream()
                .filter(s -> s.role() == CryptoArtifactRole.SECRET_KEY_CANDIDATE)
                .findFirst();
        assertTrue(sigOpt.isPresent());
        CryptoLibrarySignature sig = sigOpt.get();

        byte[] pat = sig.pattern();
        CryptoSignatureMatchReport report = matcher.scan(
                pat, 0x5000L, sig.isa(), ParserLimits.defaults(), CancellationToken.none()
        );
        assertFalse(report.findings().isEmpty());
        CryptoFinding finding = report.findings().get(0);
        assertTrue(finding.isSecret(), "SECRET_KEY_CANDIDATE must be marked secret");
        assertNotEquals(finding.rawValue(), finding.maskedValue(), "Masked value must differ from raw secret value");
        assertTrue(finding.maskedValue().contains("*"), "Masked value must contain asterisks");
    }
}
