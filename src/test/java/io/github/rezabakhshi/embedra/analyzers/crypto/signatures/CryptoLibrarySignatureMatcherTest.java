package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class CryptoLibrarySignatureMatcherTest {

    private final CryptoSignatureDatabase db = CryptoSignatureDatabase.defaultDatabase();

    private final CryptoLibrarySignatureMatcher matcher = new CryptoLibrarySignatureMatcher(db);

    @Test
    void matchesArmThumbMbedtlsAes() throws Exception {
        // Pattern for mbedtls_aes_crypt_ecb: 2de9f04f85b00090, mask: ffffffffffff00ff
        byte[] buffer = new byte[32];
        byte[] matchBytes = HexFormat.of().parseHex("2de9f04f85b0aa90"); // aa at wildcard offset 6
        System.arraycopy(matchBytes, 0, buffer, 8, matchBytes.length);

        CryptoSignatureMatchReport report = matcher.scan(
                buffer,
                0x2000L,
                CryptoIsa.ARM_THUMB,
                ParserLimits.defaults(),
                CancellationToken.none()
        );

        assertNotNull(report);
        assertEquals(1, report.totalMatched());
        CryptoFinding finding = report.findings().get(0);
        assertEquals(0x2008L, finding.address());
        assertEquals(CryptoAlgorithm.AES_128, finding.algorithm());
        assertTrue(finding.evidenceLayers().contains(CryptoEvidenceLayer.FUNCTION_SIGNATURE));
        assertEquals("MBEDTLS", finding.attributes().get("crypto.library"));
        assertEquals("ALGORITHM_IMPLEMENTATION", finding.attributes().get("crypto.artifact.role"));
        assertEquals("ARM_THUMB", finding.attributes().get("crypto.isa"));
    }

    @Test
    void matchesInlinedIdiomWithInstructionIdiomLayer() throws Exception {
        // Pattern for idiom-aes-subbytes-mixcol-thumb: ea820103ea830204, mask: ffffffffffffffff
        byte[] buffer = HexFormat.of().parseHex("ea820103ea83020400000000");

        CryptoSignatureMatchReport report = matcher.scan(
                buffer,
                0x1000L,
                CryptoIsa.ARM_THUMB,
                ParserLimits.defaults(),
                CancellationToken.none()
        );

        assertEquals(1, report.totalMatched());
        CryptoFinding finding = report.findings().get(0);
        assertEquals(CryptoArtifactRole.INLINED_IDIOM.name(), finding.attributes().get("crypto.artifact.role"));
        assertTrue(finding.evidenceLayers().contains(CryptoEvidenceLayer.FUNCTION_SIGNATURE));
        assertTrue(finding.evidenceLayers().contains(CryptoEvidenceLayer.INSTRUCTION_IDIOM));
    }

    @Test
    void matchesHardwareWrapperForEspIdf() throws Exception {
        // esp-aes-crypt-xtensa: 3641002012003100
        byte[] buffer = HexFormat.of().parseHex("3641002012003100");

        CryptoSignatureMatchReport report = matcher.scan(
                buffer,
                0x40000000L,
                CryptoIsa.XTENSA,
                ParserLimits.defaults(),
                CancellationToken.none()
        );

        assertEquals(1, report.totalMatched());
        CryptoFinding finding = report.findings().get(0);
        assertEquals("ESP_IDF", finding.attributes().get("crypto.library"));
        assertEquals(CryptoArtifactRole.WRAPPER.name(), finding.attributes().get("crypto.artifact.role"));
    }

    @Test
    void rejectsFalsePositivesOnNonCryptoData() throws Exception {
        // Repeated zeroes or arbitrary data
        byte[] nonCrypto = new byte[1024];
        for (int i = 0; i < nonCrypto.length; i++) {
            nonCrypto[i] = (byte) (i & 0xff);
        }

        CryptoSignatureMatchReport report = matcher.scan(
                nonCrypto,
                0x8000L,
                CryptoIsa.ARM_THUMB,
                ParserLimits.defaults(),
                CancellationToken.none()
        );

        assertEquals(0, report.totalMatched());
        assertTrue(report.findings().isEmpty());
    }

    @Test
    void filtersByIsa() throws Exception {
        // Xtensa signature pattern in a buffer
        byte[] buffer = HexFormat.of().parseHex("3641002012003100");

        // When scanning as ARM_THUMB, the Xtensa signature should not match
        CryptoSignatureMatchReport report = matcher.scan(
                buffer,
                0x1000L,
                CryptoIsa.ARM_THUMB,
                ParserLimits.defaults(),
                CancellationToken.none()
        );

        assertEquals(0, report.totalMatched());
    }

    @Test
    void respectsCancellation() {
        byte[] buffer = new byte[64];
        CancellationToken token = () -> true;

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                matcher.scan(buffer, 0x1000L, CryptoIsa.ARM_THUMB, ParserLimits.defaults(), token)
        );
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }
}
