package io.github.rezabakhshi.embedra.targets.esp.catalog;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded integrity-first loader for the generated offline ESP catalog. */
public final class EspDeviceCatalogLoader {
    private static final Set<String> ROOT_KEYS = Set.of(
        "schemaId", "catalogId", "snapshotDate", "generator", "sourceFactsSha256",
        "sources", "records");

    private static final Set<String> SOURCE_KEYS = Set.of(
        "identity", "url", "revision", "sha256", "license", "redistribution");

    private static final Set<String> RECORD_KEYS = Set.of(
        "recordId", "kind", "series", "exactPart", "package", "isa",
        "applicationCoreCount", "auxiliaryProcessors", "embeddedFlashMb",
        "embeddedPsramMb", "lifecycle", "firmwareChipId", "siliconRecordIds",
        "supportStates", "siliconRevision", "romIdentity", "topologyEvidence",
        "socCapabilityMacros", "peripheralCapabilities", "securityCapabilities");

    private EspDeviceCatalogLoader() {
    }

    public static EspDeviceCatalog load(
            Path directory, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        token.throwIfCancellationRequested();
        Path catalog = directory.resolve("catalog.json");
        Path checksum = directory.resolve("catalog.sha256");
        validateFile(directory, catalog);
        validateFile(directory, checksum);
        byte[] contents = readBounded(catalog, limits, token);
        String expected = readChecksum(checksum, limits, token);
        String actual = sha256(contents);
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                actual.getBytes(StandardCharsets.US_ASCII))) {
            throw failure(DiagnosticCode.ESP_CATALOG_INTEGRITY_MISMATCH,
                "ESP catalog content does not match catalog.sha256");
        }
        Object value;
        try {
            value = StrictJsonParser.parse(contents, limits, token);
        }
        catch (DiagnosticException exception) {
            if (exception.diagnostic().code() == DiagnosticCode.LIMIT_EXCEEDED
                || exception.diagnostic().code() == DiagnosticCode.CANCELLED) {
                throw exception;
            }
            throw failure(DiagnosticCode.ESP_CATALOG_INVALID,
                "ESP catalog JSON is invalid");
        }
        try {
            return parseCatalog(object(value, "catalog"), limits, token);
        }
        catch (IllegalArgumentException exception) {
            throw failure(DiagnosticCode.ESP_CATALOG_INVALID,
                "ESP catalog content is invalid: " + exception.getMessage());
        }
    }

    private static EspDeviceCatalog parseCatalog(
            Map<String, Object> root, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        exactKeys(root, ROOT_KEYS, "catalog");
        List<Object> sourceValues = array(root.get("sources"), "sources");
        List<Object> recordValues = array(root.get("records"), "records");
        if ((long) sourceValues.size() + recordValues.size() > limits.maxObjects()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP catalog exceeds the configured object limit");
        }
        List<EspCatalogSource> sources = new ArrayList<>();
        for (Object value : sourceValues) {
            token.throwIfCancellationRequested();
            Map<String, Object> source = object(value, "source");
            exactKeys(source, SOURCE_KEYS, "source");
            sources.add(new EspCatalogSource(
                string(source, "identity"), string(source, "url"),
                string(source, "revision"), string(source, "sha256"),
                string(source, "license"), string(source, "redistribution")));
        }
        List<EspCatalogRecord> records = new ArrayList<>();
        for (Object value : recordValues) {
            token.throwIfCancellationRequested();
            records.add(record(object(value, "record")));
        }
        return new EspDeviceCatalog(
            string(root, "schemaId"), string(root, "catalogId"),
            string(root, "snapshotDate"), string(root, "generator"),
            string(root, "sourceFactsSha256"), sources, records);
    }

    private static EspCatalogRecord record(Map<String, Object> value) {
        exactKeys(value, RECORD_KEYS, "record");
        Map<String, SupportState> states = new LinkedHashMap<>();
        object(value.get("supportStates"), "supportStates").forEach((key, state) ->
            states.put(key, SupportState.valueOf(text(state, "support state"))));
        return new EspCatalogRecord(
            string(value, "recordId"),
            EspCatalogEntityKind.valueOf(string(value, "kind")),
            string(value, "series"),
            string(value, "exactPart"),
            string(value, "package"),
            EspCpuIsa.valueOf(string(value, "isa")),
            integer(value, "applicationCoreCount"),
            strings(value.get("auxiliaryProcessors"), "auxiliaryProcessors"),
            string(value, "embeddedFlashMb"),
            string(value, "embeddedPsramMb"),
            string(value, "lifecycle"),
            string(value, "siliconRevision"),
            string(value, "firmwareChipId"),
            string(value, "romIdentity"),
            string(value, "topologyEvidence"),
            strings(value.get("socCapabilityMacros"), "socCapabilityMacros"),
            strings(value.get("peripheralCapabilities"), "peripheralCapabilities"),
            strings(value.get("securityCapabilities"), "securityCapabilities"),
            strings(value.get("siliconRecordIds"), "siliconRecordIds"),
            states);
    }

    private static void validateFile(Path directory, Path file) throws DiagnosticException {
        if (Files.isSymbolicLink(directory) || Files.isSymbolicLink(file)
            || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw failure(DiagnosticCode.ESP_CATALOG_INVALID,
                "ESP catalog path is missing or unsafe");
        }
    }

    private static byte[] readBounded(
            Path path, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        token.throwIfCancellationRequested();
        try {
            long size = Files.size(path);
            if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
                throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "ESP catalog exceeds the configured input limit");
            }
            byte[] result = Files.readAllBytes(path);
            token.throwIfCancellationRequested();
            return result;
        }
        catch (IOException exception) {
            throw failure(DiagnosticCode.ESP_CATALOG_INVALID,
                "ESP catalog cannot be read");
        }
    }

    private static String readChecksum(
            Path path, ParserLimits limits, CancellationToken token) throws DiagnosticException {
        byte[] bytes = readBounded(path, limits, token);
        String line = new String(bytes, StandardCharsets.US_ASCII).strip();
        if (!line.matches("[0-9a-f]{64}  catalog\\.json")) {
            throw failure(DiagnosticCode.ESP_CATALOG_INVALID,
                "ESP catalog checksum file is invalid");
        }
        return line.substring(0, 64);
    }

    private static String sha256(byte[] contents) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(contents));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }

    private static void exactKeys(Map<String, Object> value, Set<String> expected, String name) {
        if (!value.keySet().equals(expected)) {
            throw new IllegalArgumentException(name + " properties are incomplete or unknown");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value, String name) {
        if (!(value instanceof Map<?, ?> map)
            || map.keySet().stream().anyMatch(key -> !(key instanceof String))) {
            throw new IllegalArgumentException(name + " must be an object");
        }
        return (Map<String, Object>) map;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> array(Object value, String name) {
        if (!(value instanceof List<?>)) {
            throw new IllegalArgumentException(name + " must be an array");
        }
        return (List<Object>) value;
    }

    private static List<String> strings(Object value, String name) {
        return array(value, name).stream().map(item -> text(item, name + " item")).toList();
    }

    private static String string(Map<String, Object> value, String key) {
        return text(value.get(key), key);
    }

    private static String text(Object value, String name) {
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(name + " must be nonblank text");
        }
        return text;
    }

    private static int integer(Map<String, Object> value, String key) {
        if (!(value.get(key) instanceof Long number)
            || number < 0 || number > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(key + " must be a nonnegative integer");
        }
        return number.intValue();
    }

    private static DiagnosticException failure(DiagnosticCode code, String message) {
        return new DiagnosticException(Diagnostic.error(code, message, null));
    }
}
