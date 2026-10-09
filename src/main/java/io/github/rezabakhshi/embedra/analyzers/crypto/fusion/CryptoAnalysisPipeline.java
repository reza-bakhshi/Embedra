package io.github.rezabakhshi.embedra.analyzers.crypto.fusion;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoScanOptions;
import io.github.rezabakhshi.embedra.analyzers.crypto.entropy.EntropyScanner;
import io.github.rezabakhshi.embedra.analyzers.crypto.entropy.LikelyKeyScanner;
import io.github.rezabakhshi.embedra.analyzers.crypto.signatures.CryptoLibrarySignatureMatcher;
import io.github.rezabakhshi.embedra.analyzers.crypto.tables.CryptoTableDatabase;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Orchestrator and multi-layer evidence fusion engine for cryptographic artifacts (AN-003, AN-010, AN-012).
 *
 * <p>Fuses table matches, candidate key material, statistical entropy, symbols, and hardware leads into
 * unified findings while strictly differentiating ciphers from encodings, compression, and CRCs (AN-003).</p>
 */
public final class CryptoAnalysisPipeline {

    private final CryptoTableDatabase tableDatabase;

    private final EntropyScanner entropyScanner;

    private final LikelyKeyScanner keyScanner;

    private final CryptoLibrarySignatureMatcher signatureMatcher;

    public CryptoAnalysisPipeline() {
        this(new CryptoTableDatabase(), new EntropyScanner(), new LikelyKeyScanner(),
                new CryptoLibrarySignatureMatcher());
    }

    public CryptoAnalysisPipeline(
            CryptoTableDatabase tableDatabase,
            EntropyScanner entropyScanner,
            LikelyKeyScanner keyScanner) {
        this(tableDatabase, entropyScanner, keyScanner, new CryptoLibrarySignatureMatcher());
    }

    public CryptoAnalysisPipeline(
            CryptoTableDatabase tableDatabase,
            EntropyScanner entropyScanner,
            LikelyKeyScanner keyScanner,
            CryptoLibrarySignatureMatcher signatureMatcher) {
        this.tableDatabase = Objects.requireNonNull(tableDatabase, "tableDatabase must not be null");
        this.entropyScanner = Objects.requireNonNull(entropyScanner, "entropyScanner must not be null");
        this.keyScanner = Objects.requireNonNull(keyScanner, "keyScanner must not be null");
        this.signatureMatcher = Objects.requireNonNull(signatureMatcher, "signatureMatcher must not be null");
    }

    /**
     * Executes the layered cryptographic analysis pipeline over raw byte data.
     */
    public CryptoAnalysisReport analyze(
            byte[] data,
            long baseAddress,
            CryptoScanOptions options,
            List<String> symbolOrStringLeads,
            List<Long> peripheralAddresses,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(options, "options must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        List<String> stringLeads = symbolOrStringLeads == null ? List.of() : List.copyOf(symbolOrStringLeads);
        List<Long> hwLeads = peripheralAddresses == null ? List.of() : List.copyOf(peripheralAddresses);

        List<CryptoFinding> rawFindings = new ArrayList<>();

        // 1. Table and constant signatures
        if (options.scanTables()) {
            token.throwIfCancellationRequested();
            List<CryptoFinding> tableFindings = tableDatabase.scan(data, baseAddress, limits, token);
            for (CryptoFinding tf : tableFindings) {
                if (!options.scanNonCryptoEncodings() && tf.category() == CryptoCategory.ENCODING_OR_COMPRESSION) {
                    continue;
                }
                rawFindings.add(tf);
            }
        }

        // 2. High-entropy payload discovery
        if (options.scanEntropy()) {
            token.throwIfCancellationRequested();
            List<CryptoFinding> entropyFindings = entropyScanner.scan(
                    data, baseAddress, options.entropyThreshold(), limits, token);
            rawFindings.addAll(entropyFindings);
        }

        // 3. Candidate symmetric key material
        if (options.scanKeys()) {
            token.throwIfCancellationRequested();
            List<CryptoFinding> keyFindings = keyScanner.scan(data, baseAddress, limits, token);
            rawFindings.addAll(keyFindings);
        }

        // 4. Function and library signatures (AN-010, AN-011)
        if (options.scanSignatures()) {
            token.throwIfCancellationRequested();
            var sigReport = signatureMatcher.scan(data, baseAddress, null, limits, token);
            rawFindings.addAll(sigReport.findings());
        }

        // 5. Evidence fusion and confidence promotion (AN-010)
        List<CryptoFinding> fusedFindings = fuseEvidence(rawFindings, stringLeads, hwLeads);

        return new CryptoAnalysisReport(fusedFindings);
    }

    public CryptoAnalysisReport analyze(
            byte[] data,
            long baseAddress,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        return analyze(data, baseAddress, CryptoScanOptions.defaults(), List.of(), List.of(), limits, token);
    }

    private List<CryptoFinding> fuseEvidence(
            List<CryptoFinding> findings,
            List<String> stringLeads,
            List<Long> hwLeads) {

        List<CryptoFinding> fused = new ArrayList<>();
        boolean hasCipherTable = findings.stream().anyMatch(f -> f.category() == CryptoCategory.CIPHER_SYMMETRIC);

        for (CryptoFinding f : findings) {
            Set<CryptoEvidenceLayer> layers = new HashSet<>(f.evidenceLayers());
            CryptoConfidence confidence = f.confidence();

            // Check if string leads correlate with this algorithm
            boolean stringCorrelated = matchesStringLeads(f.algorithm(), stringLeads);
            if (stringCorrelated) {
                layers.add(CryptoEvidenceLayer.SYMBOL_STRING);
            }

            // Check if hardware peripherals correlate
            if (!hwLeads.isEmpty() && (f.category() == CryptoCategory.CIPHER_SYMMETRIC
                    || f.category() == CryptoCategory.HASH_MAC)) {
                layers.add(CryptoEvidenceLayer.HARDWARE_PERIPHERAL);
            }

            // Promote confidence based on multi-layer evidence
            if (f.category() == CryptoCategory.CIPHER_SYMMETRIC || f.category() == CryptoCategory.HASH_MAC) {
                if (layers.size() >= 2 && f.confidence() == CryptoConfidence.LIKELY) {
                    confidence = CryptoConfidence.CONFIRMED;
                }
            } else if (f.category() == CryptoCategory.KEY_MATERIAL) {
                // If candidate key coexists with confirmed/likely cipher tables or related symbols, elevate confidence
                if (hasCipherTable || stringCorrelated) {
                    confidence = CryptoConfidence.LIKELY;
                    if (hasCipherTable) {
                        layers.add(CryptoEvidenceLayer.DATA_FLOW);
                    }
                }
            } else if (f.category() == CryptoCategory.CHECKSUM_CRC) {
                if (stringCorrelated) {
                    confidence = CryptoConfidence.CONFIRMED;
                }
            } else if (f.category() == CryptoCategory.ENCODING_OR_COMPRESSION) {
                // Encodings and compression tables are confirmed exact fixtures
                confidence = CryptoConfidence.CONFIRMED;
            }

            // Strict differentiation verification (AN-003)
            // Verify that non-ciphers NEVER have isEncryption() true
            if (f.category() == CryptoCategory.CHECKSUM_CRC
                    || f.category() == CryptoCategory.ENTROPY_ANOMALY
                    || f.category() == CryptoCategory.ENCODING_OR_COMPRESSION
                    || f.category() == CryptoCategory.HARDWARE_SECURITY
                    || f.category() == CryptoCategory.RANDOM_GENERATOR) {
                if (f.isEncryption()) {
                    throw new IllegalStateException("Non-ciphers must not be labeled encryption: " + f);
                }
            }

            fused.add(new CryptoFinding(
                    f.id(),
                    f.address(),
                    f.length(),
                    f.category(),
                    f.algorithm(),
                    confidence,
                    layers,
                    f.explanation(),
                    f.rawValue(),
                    f.isSecret(),
                    f.attributes()
            ));
        }

        return List.copyOf(fused);
    }

    private static boolean matchesStringLeads(CryptoAlgorithm algo, List<String> stringLeads) {
        if (stringLeads.isEmpty()) {
            return false;
        }

        List<String> terms = getSearchTerms(algo);
        if (terms.isEmpty()) {
            return false;
        }

        for (String lead : stringLeads) {
            String lower = lead.toLowerCase(Locale.ROOT);
            for (String term : terms) {
                if (lower.contains(term)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<String> getSearchTerms(CryptoAlgorithm algo) {
        return switch (algo) {
            case AES_128, AES_192, AES_256 -> List.of("aes", "rijndael", "mbedtls_aes");
            case DES, TRIPLE_DES -> List.of("des", "3des", "des3", "tripledes");
            case CHACHA20, CHACHA20_POLY1305 -> List.of("chacha", "chacha20", "salsa20");
            case RC4 -> List.of("rc4", "arcfour");
            case RSA -> List.of("rsa", "pkcs");
            case DIFFIE_HELLMAN -> List.of("dh", "diffie", "hellman");
            case ECC_P256, ECC_SECP256K1, ECDSA, ECDH, CURVE25519, ED25519, X25519 ->
                    List.of("ecc", "ecdsa", "ecdh", "secp256", "curve25519", "ed25519", "x25519", "uecc");
            case MD5 -> List.of("md5", "mbedtls_md5");
            case SHA1 -> List.of("sha1", "sha-1", "mbedtls_sha1");
            case SHA224, SHA256 -> List.of("sha256", "sha-256", "sha224", "mbedtls_sha256");
            case SHA384, SHA512 -> List.of("sha512", "sha-512", "sha384", "mbedtls_sha512");
            case SHA3 -> List.of("sha3", "sha-3", "keccak");
            case BLAKE2B, BLAKE2S -> List.of("blake2", "blake2b", "blake2s");
            case POLY1305 -> List.of("poly1305");
            case HMAC, CMAC -> List.of("hmac", "cmac");
            case HKDF, PBKDF2 -> List.of("hkdf", "pbkdf2");
            case DRBG_PRNG -> List.of("drbg", "prng", "random");
            case TRNG -> List.of("trng", "rng");
            case ASN1_KEY_CERT_PARSER -> List.of("asn1", "der", "pem", "x509", "cert");
            case SECURE_BOOT -> List.of("secure_boot", "secureboot", "sb_v2", "boot_signature");
            case FLASH_ENCRYPTION -> List.of("flash_enc", "flash_encryption", "enc_write", "spi_flash_enc");
            case EFUSE_KEY_LADDER -> List.of("efuse", "key_ladder", "otp", "key_purpose");
            case SECURE_ELEMENT -> List.of("atecc", "optiga", "se050", "secure_element", "atsha");
            case CRC32 -> List.of("crc32", "crc-32", "ethernet_crc");
            case CRC16 -> List.of("crc16", "crc-16", "modbus_crc");
            case BASE64 -> List.of("base64", "b64");
            case DEFLATE_ZLIB -> List.of("deflate", "zlib", "inflate");
            case LZ4 -> List.of("lz4");
            default -> List.of();
        };
    }
}
