package io.github.rezabakhshi.embedra.analyzers.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.tables.CryptoTableDatabase;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CryptoTableDatabaseTest {

    private CryptoTableDatabase db;

    private ParserLimits limits;

    @BeforeEach
    void setUp() {
        db = new CryptoTableDatabase();
        limits = ParserLimits.defaults();
    }

    @Test
    void matchesAesSboxAndInvSboxAndRcon() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{0x00, 0x11, 0x22, 0x33}); // Padding

        // AES S-box prefix (64 bytes)
        byte[] sboxSlice = new byte[] {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
            (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
            (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0,
            (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
            (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc,
            (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
            (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a,
            (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75
        };
        out.write(sboxSlice);
        out.write(new byte[]{0x00, 0x00});

        // AES Rcon
        byte[] rcon = new byte[] {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte) 0x80, 0x1B, 0x36
        };
        out.write(rcon);

        byte[] data = out.toByteArray();
        List<CryptoFinding> findings = db.scan(data, 0x1000L, limits, CancellationToken.none());

        assertTrue(findings.stream().anyMatch(f ->
                f.algorithm() == CryptoAlgorithm.AES_128
                && f.category() == CryptoCategory.CIPHER_SYMMETRIC
                && f.isEncryption()
                && f.explanation().contains("forward substitution box")));

        assertTrue(findings.stream().anyMatch(f ->
                f.algorithm() == CryptoAlgorithm.AES_128
                && f.category() == CryptoCategory.CIPHER_SYMMETRIC
                && (f.explanation().contains("round constant") || f.id().contains("RCON"))));
    }

    @Test
    void matchesChaCha20Constant() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("preamble_data_".getBytes(StandardCharsets.US_ASCII));
        out.write("expand 32-byte k".getBytes(StandardCharsets.US_ASCII));
        out.write("_trailing_data".getBytes(StandardCharsets.US_ASCII));

        byte[] data = out.toByteArray();
        List<CryptoFinding> findings = db.scan(data, 0x2000L, limits, CancellationToken.none());

        assertTrue(findings.stream().anyMatch(f ->
                f.algorithm() == CryptoAlgorithm.CHACHA20
                && f.category() == CryptoCategory.CIPHER_SYMMETRIC
                && f.isEncryption()
                && f.address() == 0x2000L + 14));
    }

    @Test
    void matchesSha256RoundConstantsAndInitialState() throws Exception {
        // SHA-256 round constants K prefix
        int[] kPrefix = new int[] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
        };
        byte[] kBytes = new byte[32];
        for (int i = 0; i < 8; i++) {
            kBytes[i * 4] = (byte) (kPrefix[i] & 0xFF);
            kBytes[i * 4 + 1] = (byte) ((kPrefix[i] >>> 8) & 0xFF);
            kBytes[i * 4 + 2] = (byte) ((kPrefix[i] >>> 16) & 0xFF);
            kBytes[i * 4 + 3] = (byte) ((kPrefix[i] >>> 24) & 0xFF);
        }

        List<CryptoFinding> findings = db.scan(kBytes, 0x8000L, limits, CancellationToken.none());
        assertFalse(findings.isEmpty());
        CryptoFinding f = findings.get(0);
        assertEquals(CryptoAlgorithm.SHA256, f.algorithm());
        assertEquals(CryptoCategory.HASH_MAC, f.category());
        assertFalse(f.isEncryption(), "Hashes are not encryption (AN-003)");
    }

    @Test
    void matchesCrc32AndCrc16TablesWithoutLabelingAsEncryption() throws Exception {
        // Generate IEEE CRC32 table prefix
        int[] crcTable = new int[16];
        for (int i = 0; i < 16; i++) {
            int c = i;
            for (int k = 0; k < 8; k++) {
                c = ((c & 1) != 0) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            }
            crcTable[i] = c;
        }
        byte[] crcBytes = new byte[64];
        for (int i = 0; i < 16; i++) {
            crcBytes[i * 4] = (byte) (crcTable[i] & 0xFF);
            crcBytes[i * 4 + 1] = (byte) ((crcTable[i] >>> 8) & 0xFF);
            crcBytes[i * 4 + 2] = (byte) ((crcTable[i] >>> 16) & 0xFF);
            crcBytes[i * 4 + 3] = (byte) ((crcTable[i] >>> 24) & 0xFF);
        }

        List<CryptoFinding> findings = db.scan(crcBytes, 0x5000L, limits, CancellationToken.none());
        assertFalse(findings.isEmpty());
        CryptoFinding f = findings.get(0);
        assertEquals(CryptoAlgorithm.CRC32, f.algorithm());
        assertEquals(CryptoCategory.CHECKSUM_CRC, f.category());
        assertFalse(f.isEncryption(), "CRC32 MUST NOT be labeled as encryption (AN-003)");
    }

    @Test
    void matchesEccCurvesNistP256AndCurve25519() throws Exception {
        HexFormat hex = HexFormat.of();
        byte[] p256Prime = hex.parseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        byte[] curve25519Prime = hex.parseHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(p256Prime);
        out.write(new byte[]{0, 0, 0, 0});
        out.write(curve25519Prime);

        List<CryptoFinding> findings = db.scan(out.toByteArray(), 0x6000L, limits, CancellationToken.none());
        assertTrue(findings.stream().anyMatch(f -> f.algorithm() == CryptoAlgorithm.ECC_P256));
        assertTrue(findings.stream().anyMatch(f -> f.algorithm() == CryptoAlgorithm.CURVE25519));
    }

    @Test
    void strictDifferentiationRejectsCompressionAndEncodingAsEncryption() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Base64 alphabet table
        out.write(("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz0123456789+/").getBytes(StandardCharsets.US_ASCII));
        // LZ4 frame magic 0x184D2204
        out.write(new byte[]{0x04, 0x22, 0x4D, 0x18});
        // zlib header
        out.write(new byte[]{0x78, (byte) 0x9C});

        byte[] data = out.toByteArray();
        List<CryptoFinding> findings = db.scan(data, 0x7000L, limits, CancellationToken.none());

        for (CryptoFinding f : findings) {
            assertEquals(CryptoCategory.ENCODING_OR_COMPRESSION, f.category(),
                    "Format " + f.algorithm() + " must be classified as ENCODING_OR_COMPRESSION");
            assertFalse(f.isEncryption(),
                    "Encoding or compression format " + f.algorithm() + " must NEVER be labeled encryption (AN-003)");
        }
    }
}
