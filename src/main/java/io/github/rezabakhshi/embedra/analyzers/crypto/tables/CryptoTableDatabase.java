package io.github.rezabakhshi.embedra.analyzers.crypto.tables;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Immutable database and scanner for standard cryptographic constants, lookup tables,
 * and non-crypto formats (AN-003, AN-010, AN-012).
 *
 * <p>Strictly differentiates cryptographic tables from encodings and compression formats (AN-003).</p>
 */
public final class CryptoTableDatabase {

    private final List<CryptoTableSignature> signatures;

    private final List<List<CryptoTableSignature>> index = new ArrayList<>(256);

    public CryptoTableDatabase() {
        this(buildDefaultSignatures());
    }

    public CryptoTableDatabase(List<CryptoTableSignature> signatures) {
        Objects.requireNonNull(signatures, "signatures must not be null");
        this.signatures = List.copyOf(signatures);

        for (int i = 0; i < 256; i++) {
            index.add(new ArrayList<>());
        }
        for (CryptoTableSignature sig : this.signatures) {
            byte[] pat = sig.pattern();
            int firstByte = pat[0] & 0xFF;
            index.get(firstByte).add(sig);
        }
    }

    public List<CryptoTableSignature> signatures() {
        return signatures;
    }

    /**
     * Scans the provided byte array for known cryptographic constants and tables.
     */
    public List<CryptoFinding> scan(
            byte[] data,
            long baseAddress,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        int scanLength = (int) Math.min(data.length, limits.maxInputBytes());
        List<CryptoFinding> findings = new ArrayList<>();
        HexFormat hex = HexFormat.of();

        for (int i = 0; i < scanLength; i++) {
            if ((i & 0x3FFF) == 0) {
                token.throwIfCancellationRequested();
            }

            int b = data[i] & 0xFF;
            List<CryptoTableSignature> candidates = index.get(b);
            if (candidates.isEmpty()) {
                continue;
            }

            for (CryptoTableSignature sig : candidates) {
                if (sig.matches(data, i)) {
                    long addr = baseAddress + i;
                    int len = Math.min(sig.patternLength(), data.length - i);
                    byte[] sample = new byte[Math.min(len, 32)];
                    System.arraycopy(data, i, sample, 0, sample.length);

                    findings.add(new CryptoFinding(
                            sig.id() + "_" + Long.toHexString(addr),
                            addr,
                            len,
                            sig.category(),
                            sig.algorithm(),
                            CryptoConfidence.LIKELY,
                            CryptoEvidenceLayer.CONSTANT_TABLE,
                            sig.explanation(),
                            hex.formatHex(sample),
                            false // Constants and tables are public
                    ));

                    if (findings.size() >= limits.maxObjects()) {
                        return List.copyOf(findings);
                    }
                }
            }
        }

        return List.copyOf(findings);
    }

    private static List<CryptoTableSignature> buildDefaultSignatures() {
        List<CryptoTableSignature> list = new ArrayList<>();

        // 1. AES Forward S-Box (256 bytes)
        byte[] aesSbox = new byte[] {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
            (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
            (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0,
            (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
            (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc,
            (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
            (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a,
            (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75,
            (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0,
            (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84,
            (byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b,
            (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf,
            (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85,
            (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8,
            (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5,
            (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
            (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17,
            (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73,
            (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88,
            (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb,
            (byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c,
            (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79,
            (byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9,
            (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08,
            (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6,
            (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
            (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e,
            (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e,
            (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94,
            (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf,
            (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68,
            (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16
        };
        list.add(new CryptoTableSignature(
                "AES_SBOX", "AES Forward S-Box",
                CryptoCategory.CIPHER_SYMMETRIC, CryptoAlgorithm.AES_128,
                aesSbox, 64, "Standard AES Rijndael forward substitution box"));

        // 2. AES Inverse S-Box (256 bytes)
        byte[] aesInvSbox = new byte[] {
            (byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38,
            (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb,
            (byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87,
            (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb,
            (byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d,
            (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e,
            (byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2,
            (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25,
            (byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16,
            (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92,
            (byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda,
            (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84,
            (byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a,
            (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06,
            (byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02,
            (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b,
            (byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea,
            (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73,
            (byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85,
            (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e,
            (byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89,
            (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b,
            (byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20,
            (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4,
            (byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31,
            (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f,
            (byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d,
            (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef,
            (byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0,
            (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61,
            (byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26,
            (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d
        };
        list.add(new CryptoTableSignature(
                "AES_INV_SBOX", "AES Inverse S-Box",
                CryptoCategory.CIPHER_SYMMETRIC, CryptoAlgorithm.AES_128,
                aesInvSbox, 64, "Standard AES Rijndael inverse substitution box"));

        // 3. AES Rcon (Round constants)
        byte[] aesRcon = new byte[] {
            (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08,
            (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80,
            (byte) 0x1B, (byte) 0x36
        };
        list.add(new CryptoTableSignature(
                "AES_RCON", "AES Key Schedule Rcon",
                CryptoCategory.CIPHER_SYMMETRIC, CryptoAlgorithm.AES_128,
                aesRcon, "Standard AES key expansion round constant array"));

        // 4. ChaCha20 constant "expand 32-byte k" and "expand 16-byte k"
        byte[] chacha32 = "expand 32-byte k".getBytes(StandardCharsets.US_ASCII);
        list.add(new CryptoTableSignature(
                "CHACHA20_EXPAND32", "ChaCha20 Constant (32-byte key)",
                CryptoCategory.CIPHER_SYMMETRIC, CryptoAlgorithm.CHACHA20,
                chacha32, "ChaCha20 / Salsa20 32-byte key expansion constant"));

        byte[] chacha16 = "expand 16-byte k".getBytes(StandardCharsets.US_ASCII);
        list.add(new CryptoTableSignature(
                "CHACHA20_EXPAND16", "ChaCha20 Constant (16-byte key)",
                CryptoCategory.CIPHER_SYMMETRIC, CryptoAlgorithm.CHACHA20,
                chacha16, "ChaCha20 / Salsa20 16-byte key expansion constant"));

        // 5. DES Initial Permutation (IP)
        byte[] desIp = new byte[] {
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
        };
        list.add(new CryptoTableSignature(
                "DES_IP", "DES Initial Permutation (IP)",
                CryptoCategory.CIPHER_SYMMETRIC, CryptoAlgorithm.DES,
                desIp, "Standard DES initial permutation table"));

        // 6. DES Expansion Table (E)
        byte[] desE = new byte[] {
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
        };
        list.add(new CryptoTableSignature(
                "DES_E", "DES Expansion Table (E)",
                CryptoCategory.CIPHER_SYMMETRIC, CryptoAlgorithm.DES,
                desE, "Standard DES 32-to-48 bit expansion permutation table"));

        // 7. DES S-Box 1
        byte[] desS1 = new byte[] {
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
        };
        list.add(new CryptoTableSignature(
                "DES_SBOX1", "DES Substitution Box S1",
                CryptoCategory.CIPHER_SYMMETRIC, CryptoAlgorithm.DES,
                desS1, "Standard DES substitution table S1"));

        // 8. SHA-256 Round Constants K (64 words)
        int[] sha256K = new int[] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        byte[] sha256K_le = toLittleEndianBytes(sha256K);
        byte[] sha256K_be = toBigEndianBytes(sha256K);
        list.add(new CryptoTableSignature(
                "SHA256_K_LE", "SHA-256 Round Constants K (LE)",
                CryptoCategory.HASH_MAC, CryptoAlgorithm.SHA256,
                sha256K_le, 32, "SHA-256 cube-root fractional round constants (little-endian)"));
        list.add(new CryptoTableSignature(
                "SHA256_K_BE", "SHA-256 Round Constants K (BE)",
                CryptoCategory.HASH_MAC, CryptoAlgorithm.SHA256,
                sha256K_be, 32, "SHA-256 cube-root fractional round constants (big-endian)"));

        // 9. SHA-256 Initial State H (8 words)
        int[] sha256H = new int[] {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        list.add(new CryptoTableSignature(
                "SHA256_H_LE", "SHA-256 Initial State (LE)",
                CryptoCategory.HASH_MAC, CryptoAlgorithm.SHA256,
                toLittleEndianBytes(sha256H), "SHA-256 initial digest state H (little-endian)"));
        list.add(new CryptoTableSignature(
                "SHA256_H_BE", "SHA-256 Initial State (BE)",
                CryptoCategory.HASH_MAC, CryptoAlgorithm.SHA256,
                toBigEndianBytes(sha256H), "SHA-256 initial digest state H (big-endian)"));

        // 10. SHA-1 Initial State
        int[] sha1H = new int[] {
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        };
        list.add(new CryptoTableSignature(
                "SHA1_H_LE", "SHA-1 Initial State (LE)",
                CryptoCategory.HASH_MAC, CryptoAlgorithm.SHA1,
                toLittleEndianBytes(sha1H), "SHA-1 initial digest state (little-endian)"));
        list.add(new CryptoTableSignature(
                "SHA1_H_BE", "SHA-1 Initial State (BE)",
                CryptoCategory.HASH_MAC, CryptoAlgorithm.SHA1,
                toBigEndianBytes(sha1H), "SHA-1 initial digest state (big-endian)"));

        // 11. MD5 Sine Table T (64 words)
        int[] md5T = new int[] {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };
        list.add(new CryptoTableSignature(
                "MD5_T_LE", "MD5 Sine Table T (LE)",
                CryptoCategory.HASH_MAC, CryptoAlgorithm.MD5,
                toLittleEndianBytes(md5T), 32, "MD5 integer sine round table (little-endian)"));
        list.add(new CryptoTableSignature(
                "MD5_T_BE", "MD5 Sine Table T (BE)",
                CryptoCategory.HASH_MAC, CryptoAlgorithm.MD5,
                toBigEndianBytes(md5T), 32, "MD5 integer sine round table (big-endian)"));

        // 12. CRC-32 IEEE 802.3 Standard Table (256 32-bit words)
        int[] crc32Table = generateCrc32Table();
        list.add(new CryptoTableSignature(
                "CRC32_IEEE_LE", "CRC-32 Table (IEEE 802.3 LE)",
                CryptoCategory.CHECKSUM_CRC, CryptoAlgorithm.CRC32,
                toLittleEndianBytes(crc32Table), 64, "Standard IEEE 802.3 CRC-32 lookup table (little-endian)"));
        list.add(new CryptoTableSignature(
                "CRC32_IEEE_BE", "CRC-32 Table (IEEE 802.3 BE)",
                CryptoCategory.CHECKSUM_CRC, CryptoAlgorithm.CRC32,
                toBigEndianBytes(crc32Table), 64, "Standard IEEE 802.3 CRC-32 lookup table (big-endian)"));

        // 13. CRC-16 CCITT Table
        short[] crc16Ccitt = generateCrc16CcittTable();
        list.add(new CryptoTableSignature(
                "CRC16_CCITT", "CRC-16 CCITT Table",
                CryptoCategory.CHECKSUM_CRC, CryptoAlgorithm.CRC16,
                toShortBytes(crc16Ccitt), 32, "CRC-16 CCITT (0x1021) lookup table"));

        // 14. CRC-16 Modbus Table
        short[] crc16Modbus = generateCrc16ModbusTable();
        list.add(new CryptoTableSignature(
                "CRC16_MODBUS", "CRC-16 Modbus Table",
                CryptoCategory.CHECKSUM_CRC, CryptoAlgorithm.CRC16,
                toShortBytes(crc16Modbus), 32, "CRC-16 Modbus (0x8005 / 0xA001) lookup table"));

        // 15. NIST P-256 Curve Parameters
        HexFormat hex = HexFormat.of();
        byte[] p256Prime = hex.parseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        byte[] p256Gx = hex.parseHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        list.add(new CryptoTableSignature(
                "ECC_P256_PRIME", "NIST P-256 Field Prime",
                CryptoCategory.CIPHER_ASYMMETRIC, CryptoAlgorithm.ECC_P256,
                p256Prime, "NIST P-256 (secp256r1) finite field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1"));
        list.add(new CryptoTableSignature(
                "ECC_P256_GX", "NIST P-256 Base Point Gx",
                CryptoCategory.CIPHER_ASYMMETRIC, CryptoAlgorithm.ECC_P256,
                p256Gx, "NIST P-256 base generator coordinate Gx"));

        // 16. secp256k1 Curve Parameters
        byte[] secp256k1Prime = hex.parseHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        byte[] secp256k1Gx = hex.parseHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        list.add(new CryptoTableSignature(
                "ECC_SECP256K1_PRIME", "secp256k1 Field Prime",
                CryptoCategory.CIPHER_ASYMMETRIC, CryptoAlgorithm.ECC_SECP256K1,
                secp256k1Prime, "secp256k1 Koblitz curve field prime p = 2^256 - 2^32 - 977"));
        list.add(new CryptoTableSignature(
                "ECC_SECP256K1_GX", "secp256k1 Base Point Gx",
                CryptoCategory.CIPHER_ASYMMETRIC, CryptoAlgorithm.ECC_SECP256K1,
                secp256k1Gx, "secp256k1 base generator coordinate Gx"));

        // 17. Curve25519 Parameters
        byte[] curve25519PrimeBe = hex.parseHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD");
        byte[] curve25519PrimeLe = hex.parseHex("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        list.add(new CryptoTableSignature(
                "CURVE25519_PRIME_BE", "Curve25519 Field Prime (BE)",
                CryptoCategory.CIPHER_ASYMMETRIC, CryptoAlgorithm.CURVE25519,
                curve25519PrimeBe, "Montgomery Curve25519 field prime 2^255 - 19 (big-endian)"));
        list.add(new CryptoTableSignature(
                "CURVE25519_PRIME_LE", "Curve25519 Field Prime (LE)",
                CryptoCategory.CIPHER_ASYMMETRIC, CryptoAlgorithm.CURVE25519,
                curve25519PrimeLe, "Montgomery Curve25519 field prime 2^255 - 19 (little-endian)"));

        // 18. Non-Crypto Encodings & Compression (Strictly differentiated - AN-003)
        byte[] base64Alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz0123456789+/").getBytes(StandardCharsets.US_ASCII);
        list.add(new CryptoTableSignature(
                "BASE64_ALPHABET", "Base64 Standard Alphabet",
                CryptoCategory.ENCODING_OR_COMPRESSION, CryptoAlgorithm.BASE64,
                base64Alphabet, "Standard Base64 encoding character table (RFC 4648, not encryption)"));

        byte[] base64UrlAlphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz0123456789-_").getBytes(StandardCharsets.US_ASCII);
        list.add(new CryptoTableSignature(
                "BASE64_URL_ALPHABET", "Base64 URL-Safe Alphabet",
                CryptoCategory.ENCODING_OR_COMPRESSION, CryptoAlgorithm.BASE64,
                base64UrlAlphabet, "URL and filename safe Base64 character table (not encryption)"));

        // LZ4 frame magic: 0x184D2204 in little-endian (0x04, 0x22, 0x4D, 0x18)
        byte[] lz4Magic = new byte[] { 0x04, 0x22, 0x4D, 0x18 };
        list.add(new CryptoTableSignature(
                "LZ4_FRAME_MAGIC", "LZ4 Framing Format Magic",
                CryptoCategory.ENCODING_OR_COMPRESSION, CryptoAlgorithm.LZ4,
                lz4Magic, "LZ4 framing format magic header 0x184D2204 (compression, not encryption)"));

        // Deflate / zlib header constants (0x78 0x9C, 0x78 0xDA, 0x78 0x01)
        byte[] zlibDefault = new byte[] { 0x78, (byte) 0x9C };
        list.add(new CryptoTableSignature(
                "ZLIB_HEADER_DEFAULT", "zlib Default Compression Header",
                CryptoCategory.ENCODING_OR_COMPRESSION, CryptoAlgorithm.DEFLATE_ZLIB,
                zlibDefault, "Deflate / zlib standard header 0x789C (compression, not encryption)"));

        byte[] zlibMax = new byte[] { 0x78, (byte) 0xDA };
        list.add(new CryptoTableSignature(
                "ZLIB_HEADER_MAX", "zlib Max Compression Header",
                CryptoCategory.ENCODING_OR_COMPRESSION, CryptoAlgorithm.DEFLATE_ZLIB,
                zlibMax, "Deflate / zlib maximum compression header 0x78DA (compression, not encryption)"));

        return list;
    }

    private static byte[] toLittleEndianBytes(int[] words) {
        byte[] bytes = new byte[words.length * 4];
        for (int i = 0; i < words.length; i++) {
            int w = words[i];
            bytes[i * 4] = (byte) (w & 0xFF);
            bytes[i * 4 + 1] = (byte) ((w >>> 8) & 0xFF);
            bytes[i * 4 + 2] = (byte) ((w >>> 16) & 0xFF);
            bytes[i * 4 + 3] = (byte) ((w >>> 24) & 0xFF);
        }
        return bytes;
    }

    private static byte[] toBigEndianBytes(int[] words) {
        byte[] bytes = new byte[words.length * 4];
        for (int i = 0; i < words.length; i++) {
            int w = words[i];
            bytes[i * 4] = (byte) ((w >>> 24) & 0xFF);
            bytes[i * 4 + 1] = (byte) ((w >>> 16) & 0xFF);
            bytes[i * 4 + 2] = (byte) ((w >>> 8) & 0xFF);
            bytes[i * 4 + 3] = (byte) (w & 0xFF);
        }
        return bytes;
    }

    private static byte[] toShortBytes(short[] words) {
        byte[] bytes = new byte[words.length * 2];
        for (int i = 0; i < words.length; i++) {
            short w = words[i];
            bytes[i * 2] = (byte) (w & 0xFF);
            bytes[i * 2 + 1] = (byte) ((w >>> 8) & 0xFF);
        }
        return bytes;
    }

    private static int[] generateCrc32Table() {
        int[] table = new int[256];
        for (int i = 0; i < 256; i++) {
            int c = i;
            for (int k = 0; k < 8; k++) {
                c = ((c & 1) != 0) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            }
            table[i] = c;
        }
        return table;
    }

    private static short[] generateCrc16CcittTable() {
        short[] table = new short[256];
        for (int i = 0; i < 256; i++) {
            int curr = i << 8;
            for (int j = 0; j < 8; j++) {
                if ((curr & 0x8000) != 0) {
                    curr = (curr << 1) ^ 0x1021;
                } else {
                    curr <<= 1;
                }
            }
            table[i] = (short) (curr & 0xFFFF);
        }
        return table;
    }

    private static short[] generateCrc16ModbusTable() {
        short[] table = new short[256];
        for (int i = 0; i < 256; i++) {
            int curr = i;
            for (int j = 0; j < 8; j++) {
                if ((curr & 0x0001) != 0) {
                    curr = (curr >>> 1) ^ 0xA001;
                } else {
                    curr >>>= 1;
                }
            }
            table[i] = (short) (curr & 0xFFFF);
        }
        return table;
    }

    /**
     * Converts YARA rules with cryptographic metadata into CryptoTableSignatures.
     */
    public static List<CryptoTableSignature> fromYara(
            io.github.rezabakhshi.embedra.analyzers.yara.CompiledYaraRuleset ruleset) {
        Objects.requireNonNull(ruleset, "ruleset must not be null");
        List<CryptoTableSignature> result = new ArrayList<>();
        for (io.github.rezabakhshi.embedra.analyzers.yara.YaraRule rule : ruleset.rules()) {
            String catStr = rule.category();
            if (catStr == null) {
                continue;
            }
            try {
                CryptoCategory cat = CryptoCategory.valueOf(catStr);
                String algoStr = rule.algorithm();
                CryptoAlgorithm algo;
                if ("AES".equalsIgnoreCase(algoStr)) {
                    algo = CryptoAlgorithm.AES_128;
                } else if (algoStr != null) {
                    try {
                        algo = CryptoAlgorithm.valueOf(algoStr.toUpperCase());
                    } catch (IllegalArgumentException e) {
                        algo = CryptoAlgorithm.AES_128;
                    }
                } else {
                    algo = CryptoAlgorithm.AES_128;
                }
                String confStr = rule.confidence();
                CryptoConfidence conf = confStr != null ? CryptoConfidence.valueOf(confStr) : CryptoConfidence.LIKELY;
                String desc = rule.description();

                for (io.github.rezabakhshi.embedra.analyzers.yara.YaraPattern pat : rule.patterns().values()) {
                    if (pat instanceof io.github.rezabakhshi.embedra.analyzers.yara.YaraPattern.TextPattern tp) {
                        result.add(new CryptoTableSignature(
                            rule.name(), rule.name(), cat, algo,
                            tp.text().getBytes(StandardCharsets.ISO_8859_1), desc));
                    } else if (pat instanceof io.github.rezabakhshi.embedra.analyzers.yara.YaraPattern.HexPattern hp) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        for (io.github.rezabakhshi.embedra.analyzers.yara.YaraPattern.HexToken tok : hp.tokens()) {
                            if (tok instanceof io.github.rezabakhshi.embedra.analyzers.yara.YaraPattern.ByteToken bt
                                    && bt.mask() == 0xFF) {
                                baos.write(bt.value());
                            } else {
                                break;
                            }
                        }
                        byte[] bytes = baos.toByteArray();
                        if (bytes.length >= 4) {
                            result.add(new CryptoTableSignature(rule.name(), rule.name(), cat, algo, bytes, desc));
                        }
                    }
                }
            } catch (IllegalArgumentException ignored) {
                // Skip rules with non-matching enum names
            }
        }
        return Collections.unmodifiableList(result);
    }
}
