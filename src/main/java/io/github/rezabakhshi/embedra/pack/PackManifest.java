package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.report.CanonicalJson;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Versioned, provenance-complete manifest for one offline pack release. */
public record PackManifest(
        String schemaId,
        String packId,
        PackVersion version,
        String contentDigest,
        List<String> supportedDevices,
        PackProvenance provenance,
        List<PackFile> files) {
    public static final String SCHEMA_ID = "urn:embedra:schema:pack-manifest:1";

    private static final Set<String> ROOT_FIELDS = Set.of(
        "schemaId", "packId", "version", "contentDigest", "supportedDevices", "provenance",
        "files");

    private static final Set<String> PROVENANCE_FIELDS = Set.of(
        "source", "revision", "license", "transformation", "redistribution");

    private static final Set<String> FILE_FIELDS = Set.of("path", "size", "sha256");

    public PackManifest {
        Objects.requireNonNull(schemaId, "schemaId");
        requirePackId(packId);
        Objects.requireNonNull(version, "version");
        requireDigest(contentDigest, "content digest");
        supportedDevices = supportedDevices.stream().sorted().toList();
        if (supportedDevices.isEmpty()
            || new HashSet<>(supportedDevices).size() != supportedDevices.size()) {
            throw new IllegalArgumentException("Supported devices must be non-empty and unique");
        }
        supportedDevices.forEach(value -> requireIdentifier(value, "device ID"));
        Objects.requireNonNull(provenance, "provenance");
        files = files.stream().sorted(Comparator.comparing(PackFile::path)).toList();
        if (files.isEmpty() || new HashSet<>(files.stream().map(PackFile::path).toList()).size()
            != files.size()) {
            throw new IllegalArgumentException("Pack files must be non-empty and have unique paths");
        }
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new IllegalArgumentException("Unsupported pack manifest schema");
        }
        if (!contentDigest.equals(PackIntegrity.contentDigest(files))) {
            throw new IllegalArgumentException("Pack content digest does not match file descriptors");
        }
    }

    public static PackManifest parse(
            byte[] bytes, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(bytes, "bytes");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        Object parsed = StrictJsonParser.parse(bytes, limits, token);
        Map<String, Object> root = requireMap(parsed, "Pack manifest root must be an object");
        requireExactFields(root, ROOT_FIELDS);
        String schemaId = requireString(root, "schemaId");
        if (!SCHEMA_ID.equals(schemaId)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_SCHEMA_UNSUPPORTED,
                "Unsupported pack manifest schema");
        }
        PackProvenance provenance = parseProvenance(requireMap(root.get("provenance"),
            "Pack provenance must be an object"));
        List<String> devices = parseDevices(root.get("supportedDevices"));
        List<PackFile> files = parseFiles(root.get("files"));
        try {
            return new PackManifest(schemaId, requireString(root, "packId"),
                PackVersion.parse(requireString(root, "version")),
                requireString(root, "contentDigest"), devices, provenance, files);
        }
        catch (IllegalArgumentException | NullPointerException exception) {
            DiagnosticCode code = exception.getMessage() != null
                && exception.getMessage().contains("path")
                    ? DiagnosticCode.PACK_PATH_UNSAFE : DiagnosticCode.PACK_MANIFEST_INVALID;
            if (exception.getMessage() != null && exception.getMessage().contains("content digest")) {
                code = DiagnosticCode.PACK_INTEGRITY_MISMATCH;
            }
            throw PackDiagnostics.failure(code, "Invalid pack manifest: " + safeMessage(exception));
        }
    }

    public static PackManifest read(
            Path manifestPath, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(manifestPath, "manifestPath");
        token.throwIfCancellationRequested();
        try {
            if (!Files.isRegularFile(manifestPath) || Files.isSymbolicLink(manifestPath)) {
                throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID,
                    "Pack manifest is not a regular file");
            }
            long size = Files.size(manifestPath);
            if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
                throw PackDiagnostics.failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "Pack manifest exceeds the configured input limit");
            }
            return parse(Files.readAllBytes(manifestPath), limits, token);
        }
        catch (IOException exception) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID,
                "Pack manifest could not be read");
        }
    }

    public String toCanonicalJson() {
        return CanonicalJson.write(canonicalValue());
    }

    Map<String, Object> canonicalValue() {
        return Map.of(
            "schemaId", schemaId,
            "packId", packId,
            "version", version.toString(),
            "contentDigest", contentDigest,
            "supportedDevices", supportedDevices,
            "provenance", Map.of(
                "source", provenance.source().toString(),
                "revision", provenance.revision(),
                "license", provenance.license(),
                "transformation", provenance.transformation(),
                "redistribution", provenance.redistribution().name()),
            "files", files.stream().map(file -> Map.<String, Object>of(
                "path", file.path(), "size", file.size(), "sha256", file.sha256())).toList());
    }

    static void requirePackId(String value) {
        Objects.requireNonNull(value, "packId");
        if (!value.matches("[a-z0-9]+(?:[.-][a-z0-9]+)*")) {
            throw new IllegalArgumentException("Pack ID contains unsupported characters");
        }
    }

    static void requireIdentifier(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank() || value.indexOf('\0') >= 0 || value.indexOf('/') >= 0
            || value.indexOf('\\') >= 0) {
            throw new IllegalArgumentException(field + " is invalid");
        }
    }

    private static PackProvenance parseProvenance(Map<String, Object> value)
            throws DiagnosticException {
        requireExactFields(value, PROVENANCE_FIELDS);
        try {
            return new PackProvenance(new URI(requireString(value, "source")),
                requireString(value, "revision"), requireString(value, "license"),
                requireString(value, "transformation"),
                RedistributionStatus.valueOf(requireString(value, "redistribution")));
        }
        catch (IllegalArgumentException | NullPointerException | URISyntaxException exception) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_PROVENANCE_INVALID,
                "Invalid pack provenance: " + safeMessage(exception));
        }
    }

    private static List<String> parseDevices(Object value) throws DiagnosticException {
        List<Object> values = requireList(value, "Supported devices must be an array");
        ArrayList<String> result = new ArrayList<>();
        for (Object item : values) {
            if (!(item instanceof String text)) {
                throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID,
                    "Supported device ID must be a string");
            }
            result.add(text);
        }
        return result;
    }

    private static List<PackFile> parseFiles(Object value) throws DiagnosticException {
        List<Object> values = requireList(value, "Pack files must be an array");
        ArrayList<PackFile> result = new ArrayList<>();
        for (Object item : values) {
            Map<String, Object> file = requireMap(item, "Pack file entry must be an object");
            requireExactFields(file, FILE_FIELDS);
            try {
                result.add(new PackFile(requireString(file, "path"), requireLong(file, "size"),
                    requireString(file, "sha256")));
            }
            catch (IllegalArgumentException | NullPointerException exception) {
                DiagnosticCode code = exception.getMessage() != null
                    && exception.getMessage().contains("path")
                        ? DiagnosticCode.PACK_PATH_UNSAFE : DiagnosticCode.PACK_MANIFEST_INVALID;
                throw PackDiagnostics.failure(code,
                    "Invalid pack file entry: " + safeMessage(exception));
            }
        }
        return result;
    }

    private static void requireExactFields(Map<String, Object> map, Set<String> expected)
            throws DiagnosticException {
        if (!map.keySet().equals(expected)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID,
                "Pack manifest fields do not match schema");
        }
    }

    private static String requireString(Map<String, Object> map, String key)
            throws DiagnosticException {
        Object value = map.get(key);
        if (!(value instanceof String text)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID,
                "Pack manifest field must be a string: " + key);
        }
        return text;
    }

    private static long requireLong(Map<String, Object> map, String key) throws DiagnosticException {
        Object value = map.get(key);
        if (!(value instanceof Long number)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID,
                "Pack manifest field must be an integer: " + key);
        }
        return number;
    }

    private static Map<String, Object> requireMap(Object value, String message)
            throws DiagnosticException {
        if (!(value instanceof Map<?, ?> untyped)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID, message);
        }
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : untyped.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID, message);
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static List<Object> requireList(Object value, String message)
            throws DiagnosticException {
        if (!(value instanceof List<?> list)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID, message);
        }
        return new ArrayList<>(list);
    }

    private static void requireDigest(String value, String field) {
        Objects.requireNonNull(value, field);
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }

    private static String safeMessage(Exception exception) {
        return exception.getMessage() == null ? "invalid value" : exception.getMessage();
    }
}
