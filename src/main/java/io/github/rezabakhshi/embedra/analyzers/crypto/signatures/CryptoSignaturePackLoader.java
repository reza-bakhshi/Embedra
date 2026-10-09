package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Validated, bounded loader for cryptographic signature packs (AN-011, CORE-003, CORE-013).
 */
public final class CryptoSignaturePackLoader {

    private CryptoSignaturePackLoader() {
    }

    public static CryptoSignaturePack load(
            byte[] bytes,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(bytes, "bytes must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        Object parsed = CryptoSignatureJsonParser.parse(bytes, limits, token);
        if (!(parsed instanceof Map<?, ?> rawMap)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID,
                    "Root of signature pack must be a JSON object", null));
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> root = (Map<String, Object>) rawMap;

        String schemaId = getString(root, "schemaId");
        if (!CryptoSignaturePack.SCHEMA_ID.equals(schemaId)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID,
                    "Unsupported schemaId: " + schemaId, null));
        }

        String packId = getString(root, "packId");
        String version = getString(root, "version");
        String description = getString(root, "description");
        String expectedDigest = getString(root, "integrityDigest");

        Object rawSignatures = root.get("signatures");
        if (!(rawSignatures instanceof List<?> list)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID,
                    "signatures property must be an array", null));
        }

        List<CryptoLibrarySignature> signatures = new ArrayList<>();
        for (Object item : list) {
            token.throwIfCancellationRequested();
            if (!(item instanceof Map<?, ?> rawSig)) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID,
                        "Signature item must be an object", null));
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> sigMap = (Map<String, Object>) rawSig;
            signatures.add(parseSignature(sigMap));
        }

        if (signatures.isEmpty()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID,
                    "Signature pack must contain at least one signature", null));
        }

        String computedDigest = computeIntegrityDigest(signatures);
        if (!computedDigest.equalsIgnoreCase(expectedDigest)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_SIGNATURE_INTEGRITY_MISMATCH,
                    "Integrity digest mismatch. Expected " + expectedDigest + " but computed " + computedDigest,
                    null));
        }

        return new CryptoSignaturePack(
                schemaId,
                packId,
                version,
                description,
                signatures,
                expectedDigest
        );
    }

    private static CryptoLibrarySignature parseSignature(Map<String, Object> map) throws DiagnosticException {
        try {
            String id = getString(map, "id");
            String name = getString(map, "name");
            CryptoLibrary library = CryptoLibrary.valueOf(getString(map, "library"));
            CryptoAlgorithm algorithm = CryptoAlgorithm.valueOf(getString(map, "algorithm"));
            CryptoArtifactRole role = CryptoArtifactRole.valueOf(getString(map, "role"));
            CryptoIsa isa = CryptoIsa.valueOf(getString(map, "isa"));
            CryptoCompiler compiler = CryptoCompiler.valueOf(getString(map, "compiler"));
            CryptoOptimization optimization = CryptoOptimization.valueOf(getString(map, "optimization"));
            CryptoConfidence confidence = CryptoConfidence.valueOf(getString(map, "confidence"));

            Object rawProv = map.get("provenance");
            if (!(rawProv instanceof Map<?, ?> provMap)) {
                throw new IllegalArgumentException("provenance must be an object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> prov = (Map<String, Object>) provMap;
            CryptoSignatureProvenance provenance = new CryptoSignatureProvenance(
                    getString(prov, "library"),
                    getString(prov, "version"),
                    getString(prov, "license"),
                    getString(prov, "sourceFile"),
                    getString(prov, "sourceSha256")
            );

            byte[] pattern = parseHex(getString(map, "pattern"));
            byte[] mask = parseHex(getString(map, "mask"));

            List<String> symbols = new ArrayList<>();
            Object rawSymbols = map.get("crossReferenceSymbols");
            if (rawSymbols instanceof List<?> symList) {
                for (Object s : symList) {
                    if (s instanceof String str && !str.isBlank()) {
                        symbols.add(str);
                    }
                }
            }

            return new CryptoLibrarySignature(
                    id, name, library, algorithm, role, isa, compiler, optimization,
                    confidence, provenance, pattern, mask, symbols
            );
        } catch (IllegalArgumentException e) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_SIGNATURE_INVALID,
                    "Invalid signature definition: " + e.getMessage(), null));
        }
    }

    public static String computeIntegrityDigest(List<CryptoLibrarySignature> signatures) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            signatures.stream().sorted(Comparator.comparing(CryptoLibrarySignature::id)).forEach(sig -> {
                String descriptor = sig.id() + '\0'
                        + sig.library().name() + '\0'
                        + sig.algorithm().name() + '\0'
                        + sig.role().name() + '\0'
                        + sig.isa().name() + '\0'
                        + sig.compiler().name() + '\0'
                        + sig.optimization().name() + '\0'
                        + HexFormat.of().formatHex(sig.pattern()) + '\0'
                        + HexFormat.of().formatHex(sig.mask()) + '\0'
                        + sig.provenance().sourceSha256() + '\n';
                digest.update(descriptor.getBytes(StandardCharsets.UTF_8));
            });
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static String getString(Map<String, Object> map, String key) throws DiagnosticException {
        Object val = map.get(key);
        if (!(val instanceof String s) || s.isBlank()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID,
                    "Missing or empty required string property: " + key, null));
        }
        return s;
    }

    private static byte[] parseHex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length: " + hex);
        }
        return HexFormat.of().parseHex(hex);
    }
}
