package io.github.rezabakhshi.embedra.analyzers.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.entropy.LikelyKeyScanner;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LikelyKeyScannerTest {

    private LikelyKeyScanner scanner;

    private ParserLimits limits;

    private HexFormat hex;

    @BeforeEach
    void setUp() {
        scanner = new LikelyKeyScanner();
        limits = ParserLimits.defaults();
        hex = HexFormat.of();
    }

    @Test
    void discoversLikelySymmetricKeysAndMasksValue() throws Exception {
        // High-entropy 16-byte and 32-byte keys with distinct random bytes
        byte[] key16 = hex.parseHex("4a2f8b91c0e357d629a8f413b5e2786d");
        byte[] key32 = hex.parseHex("9d3f1a7b8c2e4056ef98234157a0bcde1234567890abcdef13579bdf2468ace0");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{0x00, 0x00, 0x00, 0x00}); // Alignment
        out.write(key16);
        out.write(new byte[]{0x00, 0x00, 0x00, 0x00});
        out.write(key32);

        byte[] data = out.toByteArray();
        List<CryptoFinding> findings = scanner.scan(data, 0x20000000L, limits, CancellationToken.none());

        assertTrue(findings.stream().anyMatch(f ->
                f.length() == 16
                && f.category() == CryptoCategory.KEY_MATERIAL
                && f.algorithm() == CryptoAlgorithm.AES_128
                && f.isSecret()));

        assertTrue(findings.stream().anyMatch(f ->
                f.length() == 32
                && f.category() == CryptoCategory.KEY_MATERIAL
                && f.algorithm() == CryptoAlgorithm.AES_256
                && f.isSecret()));

        for (CryptoFinding f : findings) {
            assertTrue(f.isSecret());
            String masked = f.maskedValue();
            assertNotEquals(f.rawValue(), masked, "Secret key must be masked");
            assertTrue(masked.contains("*"), "Masked key must contain asterisks");
            assertEquals(f.rawValue().substring(0, 4), masked.substring(0, 4));
        }
    }

    @Test
    void rejectsFalsePositiveRepetitiveAndZeroPatterns() {
        // Zero runs
        byte[] allZeros = new byte[16];
        assertFalse(LikelyKeyScanner.isLikelyKeyMaterial(allZeros, 0, 16));

        byte[] withZeroRun = hex.parseHex("4a2f8b91000057d629a8f413b5e2786d");
        assertFalse(LikelyKeyScanner.isLikelyKeyMaterial(withZeroRun, 0, 16));

        // Repetitive 2-byte pattern (0xAA 0x55 0xAA 0x55...)
        byte[] repeating2 = hex.parseHex("aa55aa55aa55aa55aa55aa55aa55aa55");
        assertFalse(LikelyKeyScanner.isLikelyKeyMaterial(repeating2, 0, 16));

        // Repetitive 4-byte pattern (0xDE 0xAD 0xBE 0xEF...)
        byte[] repeating4 = hex.parseHex("deadbeefdeadbeefdeadbeefdeadbeef");
        assertFalse(LikelyKeyScanner.isLikelyKeyMaterial(repeating4, 0, 16));
    }

    @Test
    void rejectsAsciiStringsAsCandidateKeys() {
        byte[] asciiStr = "MyCustomSecretKeyPassword!".getBytes(StandardCharsets.US_ASCII);
        assertFalse(LikelyKeyScanner.isLikelyKeyMaterial(asciiStr, 0, 16));
        assertFalse(LikelyKeyScanner.isLikelyKeyMaterial(asciiStr, 0, 24));
    }

    @Test
    void rejectsCodeInstructionPatterns() {
        // Thumb NOP sequence (0x00 0xBF repeated)
        byte[] thumbNops = hex.parseHex("00bf00bf00bf00bf00bf00bf00bf00bf");
        assertFalse(LikelyKeyScanner.isLikelyKeyMaterial(thumbNops, 0, 16));

        // ARM32 NOP sequence (0xE1A00000)
        byte[] armNops = hex.parseHex("0000a0e10000a0e10000a0e10000a0e1");
        assertFalse(LikelyKeyScanner.isLikelyKeyMaterial(armNops, 0, 16));
    }
}
