package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.PackIntegrity;
import io.github.rezabakhshi.embedra.pack.PackManifest;
import io.github.rezabakhshi.embedra.pack.PackProvenance;
import io.github.rezabakhshi.embedra.pack.RedistributionStatus;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Integrity-first loader for generated STM32 library signature packs.
 *
 * <p>Loading verifies the pack identity, the pinned redistributable provenance,
 * the aggregate content digest, and the closed content schema before a single
 * signature is exposed. A malformed, truncated, oversized, duplicate, or
 * out-of-range entry fails closed with a stable diagnostic.</p>
 */
public final class Stm32SignaturePackLoader {
    public static final String CONTENT_SCHEMA = "urn:embedra:schema:stm32-signature-pack:1";

    public static final String PACK_ID = "stm32.stm32f1.signatures";

    public static final String SERIES = "STM32F1";

    public static final String SOURCE_PACKAGE = "STM32Cube_FW_F1_V1.8.7";

    public static final String LICENSE = "BSD-3-Clause AND Apache-2.0 AND MIT";

    private static final String CONTENT_FILE = "signatures.json";

    private static final Set<String> ROOT_FIELDS =
        Set.of("$schema", "sourcePackage", "series", "signatures");

    private static final Set<String> SIGNATURE_FIELDS = Set.of("signatureId", "library",
        "component", "functionName", "family", "compiler", "optimization", "sourceFile",
        "sourceSha256", "pattern", "mask");

    private Stm32SignaturePackLoader() {
    }

    public static Stm32SignaturePack load(Path directory, ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        token.throwIfCancellationRequested();
        PackManifest manifest = PackManifest.read(directory.resolve("pack.json"), limits, token);
        if (!manifest.packId().equals(PACK_ID) || manifest.files().size() != 1
                || !manifest.files().get(0).path().equals(CONTENT_FILE)) {
            throw failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "STM32 signature pack identity or content kind is incompatible");
        }
        PackProvenance provenance = manifest.provenance();
        if (!LICENSE.equals(provenance.license())
                || !SOURCE_PACKAGE.equals(provenance.revision())
                || provenance.redistribution() != RedistributionStatus.ALLOWED) {
            throw failure(DiagnosticCode.PACK_PROVENANCE_INVALID,
                "STM32 signature pack provenance is not the pinned redistributable source");
        }
        PackIntegrity.verify(directory, manifest, limits, token);
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(directory.resolve(CONTENT_FILE));
        }
        catch (IOException exception) {
            throw failure(DiagnosticCode.PACK_CONTENT_INVALID,
                "Verified STM32 signature pack content could not be read");
        }
        Map<String, Object> root = object(StrictJsonParser.parse(bytes, limits, token),
            "Signature pack root must be an object");
        exact(root, ROOT_FIELDS);
        if (!CONTENT_SCHEMA.equals(string(root, "$schema"))
                || !SOURCE_PACKAGE.equals(string(root, "sourcePackage"))
                || !SERIES.equals(string(root, "series"))) {
            throw failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "Signature content identity does not match its manifest");
        }
        List<Stm32LibrarySignature> signatures = new ArrayList<>();
        for (Object value : array(root.get("signatures"),
                "Signature pack signatures must be an array")) {
            token.throwIfCancellationRequested();
            signatures.add(signature(value));
        }
        if (signatures.isEmpty()) {
            throw invalid("Signature pack must contain at least one signature");
        }
        try {
            return new Stm32SignaturePack(manifest, signatures);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid signature pack: " + safeMessage(exception));
        }
    }

    private static Stm32LibrarySignature signature(Object value) throws DiagnosticException {
        Map<String, Object> item = object(value, "Signature must be an object");
        exact(item, SIGNATURE_FIELDS);
        try {
            return new Stm32LibrarySignature(string(item, "signatureId"),
                string(item, "library"), string(item, "component"),
                string(item, "functionName"), string(item, "family"),
                string(item, "compiler"), string(item, "optimization"),
                string(item, "sourceFile"), string(item, "sourceSha256"),
                decodeHex(string(item, "pattern"), "pattern"),
                decodeHex(string(item, "mask"), "mask"));
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid signature: " + safeMessage(exception));
        }
    }

    private static byte[] decodeHex(String value, String field) {
        if (value.length() % 2 != 0 || !value.matches("[0-9a-f]*")) {
            throw new IllegalArgumentException("Signature " + field + " is not lowercase hex");
        }
        byte[] decoded = new byte[value.length() / 2];
        for (int index = 0; index < decoded.length; index++) {
            decoded[index] = (byte) Integer.parseInt(
                value.substring(index * 2, index * 2 + 2), 16);
        }
        return decoded;
    }

    private static Map<String, Object> object(Object value, String message)
            throws DiagnosticException {
        if (!(value instanceof Map<?, ?> map)) {
            throw invalid(message);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw invalid(message);
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static List<Object> array(Object value, String message) throws DiagnosticException {
        if (!(value instanceof List<?> list)) {
            throw invalid(message);
        }
        return new ArrayList<>(list);
    }

    private static String string(Map<String, Object> map, String key) throws DiagnosticException {
        Object value = map.get(key);
        if (!(value instanceof String text)) {
            throw invalid("Signature field must be a string: " + key);
        }
        return text;
    }

    private static void exact(Map<String, Object> map, Set<String> fields)
            throws DiagnosticException {
        if (!map.keySet().equals(fields)) {
            throw invalid("Signature pack fields do not match the closed schema");
        }
    }

    private static DiagnosticException invalid(String message) {
        return failure(DiagnosticCode.PACK_CONTENT_INVALID, message);
    }

    private static DiagnosticException failure(DiagnosticCode code, String message) {
        return new DiagnosticException(Diagnostic.error(code, message, null));
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank()
            ? exception.getClass().getSimpleName() : message;
    }
}
