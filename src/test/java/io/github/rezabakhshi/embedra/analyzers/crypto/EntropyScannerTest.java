package io.github.rezabakhshi.embedra.analyzers.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.entropy.EntropyResult;
import io.github.rezabakhshi.embedra.analyzers.crypto.entropy.EntropyScanner;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Random;
import java.util.zip.Deflater;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EntropyScannerTest {

    private EntropyScanner scanner;

    private ParserLimits limits;

    @BeforeEach
    void setUp() {
        scanner = new EntropyScanner();
        limits = ParserLimits.defaults();
    }

    @Test
    void evaluatesUniformRandomCiphertextAsHighEntropy() {
        byte[] randomBytes = new byte[1024];
        new Random(42).nextBytes(randomBytes);

        EntropyResult result = EntropyScanner.calculate(randomBytes, 0, randomBytes.length);
        assertTrue(result.entropy() >= 7.6,
                "Random uniform bytes must exhibit entropy >= 7.6, got " + result.entropy());
        assertTrue(result.highEntropy());
        assertTrue(result.likelyCiphertext());
        assertFalse(result.likelyCompressed());
    }

    @Test
    void rejectsZeroPaddedAndLowEntropyStreams() {
        byte[] zeroBytes = new byte[512];
        EntropyResult result = EntropyScanner.calculate(zeroBytes, 0, zeroBytes.length);

        assertEquals(0.0, result.entropy(), 0.001);
        assertFalse(result.highEntropy());
        assertFalse(result.likelyCiphertext());
    }

    @Test
    void differentiatesCompressedStreamFromCiphertext() {
        // Generate pseudo-patterned structured text and compress with Deflater (zlib)
        byte[] input = new byte[8192];
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) ((i * 37 + (i % 19) * 11) & 0xFF);
        }
        byte[] output = new byte[input.length * 2];
        Deflater deflater = new Deflater();
        deflater.setInput(input);
        deflater.finish();
        int compressedLen = deflater.deflate(output);
        deflater.end();

        assertTrue(compressedLen >= 256, "Compressed length should be at least 256 bytes");

        EntropyResult result = EntropyScanner.calculate(output, 0, compressedLen);
        assertTrue(result.likelyCompressed(), "Stream starting with zlib header must be identified as compressed");
    }

    @Test
    void mergesSlidingWindowsIntoFindingsWithoutLabelingAsEncryption() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[512]); // Low entropy zeroes
        byte[] randomChunk = new byte[1024];
        new Random(12345).nextBytes(randomChunk);
        out.write(randomChunk); // High entropy
        out.write(new byte[512]); // Low entropy zeroes

        byte[] data = out.toByteArray();
        List<CryptoFinding> findings = scanner.scan(data, 0x10000L, 7.2, limits, CancellationToken.none());

        assertFalse(findings.isEmpty());
        CryptoFinding f = findings.get(0);
        assertEquals(CryptoCategory.ENTROPY_ANOMALY, f.category());
        assertEquals(CryptoAlgorithm.HIGH_ENTROPY_BLOCK, f.algorithm());
        assertFalse(f.isEncryption(), "Entropy anomalies alone MUST NOT be labeled as encryption (AN-003)");
        assertTrue(f.length() >= 512);
    }
}
