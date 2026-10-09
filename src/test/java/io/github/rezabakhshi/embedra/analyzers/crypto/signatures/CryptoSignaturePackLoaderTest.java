package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.junit.jupiter.api.Test;

class CryptoSignaturePackLoaderTest {

    private static final String ZERO_DIGEST = "0".repeat(64);

    private static final String SAMPLE_PACK_JSON_TEMPLATE = """
            {
              "schemaId": "urn:embedra:schema:crypto-signature-pack:1",
              "packId": "sample-crypto-pack",
              "version": "1.0.0",
              "description": "Sample embedded crypto signature pack",
              "integrityDigest": "%s",
              "signatures": [
                {
                  "id": "mbedtls-aes-ecb-thumb",
                  "name": "mbedtls_aes_crypt_ecb",
                  "library": "MBEDTLS",
                  "algorithm": "AES_128",
                  "role": "ALGORITHM_IMPLEMENTATION",
                  "isa": "ARM_THUMB",
                  "compiler": "GCC",
                  "optimization": "O2",
                  "confidence": "CONFIRMED",
                  "provenance": {
                    "library": "mbedtls",
                    "version": "3.4.0",
                    "license": "Apache-2.0",
                    "sourceFile": "library/aes.c",
                    "sourceSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                  },
                  "pattern": "2de9f04f85b00090",
                  "mask": "ffffffffffff00ff",
                  "crossReferenceSymbols": ["mbedtls_aes_crypt_ecb"]
                }
              ]
            }
            """;

    private static String computePayloadDigest(String jsonWithoutDigest) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(jsonWithoutDigest.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void loadsValidPack() throws Exception {
        CryptoSignatureProvenance prov = new CryptoSignatureProvenance(
                "mbedtls", "3.4.0", "Apache-2.0", "library/aes.c",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        byte[] pat = java.util.HexFormat.of().parseHex("2de9f04f85b00090");
        byte[] mask = java.util.HexFormat.of().parseHex("ffffffffffff00ff");
        CryptoLibrarySignature sig = new CryptoLibrarySignature(
                "mbedtls-aes-ecb-thumb",
                "mbedtls_aes_crypt_ecb",
                CryptoLibrary.MBEDTLS,
                CryptoAlgorithm.AES_128,
                CryptoArtifactRole.ALGORITHM_IMPLEMENTATION,
                CryptoIsa.ARM_THUMB,
                CryptoCompiler.GCC,
                CryptoOptimization.O2,
                CryptoConfidence.CONFIRMED,
                prov,
                pat,
                mask,
                List.of("mbedtls_aes_crypt_ecb")
        );
        String digest = CryptoSignaturePackLoader.computeIntegrityDigest(List.of(sig));
        String fullJson = String.format(SAMPLE_PACK_JSON_TEMPLATE, digest);

        CryptoSignaturePack pack = CryptoSignaturePackLoader.load(
                fullJson.getBytes(StandardCharsets.UTF_8),
                ParserLimits.defaults(),
                CancellationToken.none()
        );

        assertNotNull(pack);
        assertEquals("sample-crypto-pack", pack.packId());
        assertEquals("1.0.0", pack.version());
        assertEquals(1, pack.signatures().size());
        CryptoLibrarySignature loadedSig = pack.signatures().get(0);
        assertEquals("mbedtls-aes-ecb-thumb", loadedSig.id());
        assertEquals(CryptoLibrary.MBEDTLS, loadedSig.library());
        assertEquals(8, loadedSig.length());
    }

    @Test
    void rejectsIntegrityMismatch() {
        String badDigestJson = String.format(SAMPLE_PACK_JSON_TEMPLATE, ZERO_DIGEST);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                CryptoSignaturePackLoader.load(
                        badDigestJson.getBytes(StandardCharsets.UTF_8),
                        ParserLimits.defaults(),
                        CancellationToken.none()
                )
        );
        assertEquals(DiagnosticCode.CRYPTO_SIGNATURE_INTEGRITY_MISMATCH, ex.diagnostic().code());
    }

    @Test
    void rejectsUnsupportedSchema() {
        String badSchemaJson = """
                {
                  "schemaId": "urn:embedra:schema:unknown-pack:1",
                  "packId": "sample",
                  "version": "1.0.0",
                  "description": "desc",
                  "integrityDigest": "%s",
                  "signatures": []
                }
                """.formatted(ZERO_DIGEST);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                CryptoSignaturePackLoader.load(
                        badSchemaJson.getBytes(StandardCharsets.UTF_8),
                        ParserLimits.defaults(),
                        CancellationToken.none()
                )
        );
        assertEquals(DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID, ex.diagnostic().code());
    }

    @Test
    void respectsCancellation() {
        CancellationToken token = () -> true;
        String json = String.format(SAMPLE_PACK_JSON_TEMPLATE, ZERO_DIGEST);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                CryptoSignaturePackLoader.load(
                        json.getBytes(StandardCharsets.UTF_8),
                        ParserLimits.defaults(),
                        token
                )
        );
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }

    @Test
    void respectsLimits() {
        String json = String.format(SAMPLE_PACK_JSON_TEMPLATE, ZERO_DIGEST);
        ParserLimits tinyLimit = new ParserLimits(10, 10, 10, 10, 10, java.time.Duration.ofSeconds(1));

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                CryptoSignaturePackLoader.load(
                        json.getBytes(StandardCharsets.UTF_8),
                        tinyLimit,
                        CancellationToken.none()
                )
        );
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }
}
