package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.RedistributionStatus;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validated provenance contract for one ESP32-S3 ESP-IDF Function ID pilot database.
 *
 * <p>The descriptor binds a Ghidra {@code .fidb} file to its exact reference build:
 * target, language variant, ESP-IDF revision, toolchain, optimization, component
 * license audit, and content digests. Host paths are rejected so the contract stays
 * relocatable and free of machine identity.</p>
 */
public record Esp32S3FidProvenance(
        String schemaId,
        String artifactId,
        String targetId,
        int chipId,
        String languageId,
        String compilerSpecId,
        String idfVersion,
        String idfRevision,
        String toolchain,
        String optimization,
        String sdkconfigSha256,
        String referenceElfSha256,
        String strippedImageSha256,
        String fidbSha256,
        int functionCount,
        String generatorCommand,
        String ghidraVersion,
        String libraryFamily,
        String libraryVersion,
        String libraryVariant,
        List<Esp32S3FidComponent> components,
        RedistributionStatus redistribution) {
    public static final String SCHEMA_ID = "urn:embedra:schema:esp32s3-fidb-provenance:1";

    private static final String ESP32S3_TARGET = "esp32s3";

    private static final String ESP32S3_LANGUAGE = "Xtensa:LE:32:esp32s3";

    private static final int ESP32S3_CHIP_ID = 9;

    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");

    private static final Pattern GIT_REVISION = Pattern.compile("^[0-9a-f]{40}$");

    private static final Pattern OPTIMIZATION = Pattern.compile("^O[s0-3]$");

    private static final Pattern VERSION = Pattern.compile("^[0-9]+\\.[0-9]+\\.[0-9]+$");

    private static final List<String> HOST_PATH_MARKERS = List.of(
        "/home/", "/root/", "/tmp/", "/private/var/", "/Users/", ".ssh/");

    private static final Set<String> REQUIRED_KEYS = Set.of(
        "schemaId", "artifactId", "targetId", "chipId", "languageId", "compilerSpecId",
        "idfVersion", "idfRevision", "toolchain", "optimization", "sdkconfigSha256",
        "referenceElfSha256", "strippedImageSha256", "fidbSha256", "functionCount",
        "generatorCommand", "ghidraVersion", "libraryFamily", "libraryVersion",
        "libraryVariant", "components", "redistribution");

    private static final Set<String> COMPONENT_KEYS = Set.of("name", "license", "redistribution");

    public Esp32S3FidProvenance {
        Objects.requireNonNull(schemaId, "schemaId");
        Objects.requireNonNull(components, "components");
        components = List.copyOf(components);
        if (components.isEmpty()) {
            throw new IllegalArgumentException("Component license audit must be non-empty");
        }
        if (redistribution == RedistributionStatus.ALLOWED && components.stream()
            .anyMatch(component -> component.redistribution() != RedistributionStatus.ALLOWED)) {
            throw new IllegalArgumentException(
                "Bundled redistribution requires every component to be allowed");
        }
    }

    public static Esp32S3FidProvenance parse(byte[] json, ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        token.throwIfCancellationRequested();
        Object parsed = StrictJsonParser.parse(json, limits, token);
        if (!(parsed instanceof Map<?, ?> rootValue)) {
            throw invalid("Provenance descriptor root must be an object");
        }
        Map<String, Object> root = requireClosedKeys(castKeys(rootValue), REQUIRED_KEYS);
        String schemaId = requireText(root, "schemaId", 128);
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ESP_FID_PROVENANCE_SCHEMA_UNSUPPORTED,
                "Unsupported ESP32-S3 Function ID provenance schema: " + schemaId, null));
        }
        try {
            String targetId = requireText(root, "targetId", 32);
            String languageId = requireText(root, "languageId", 64);
            String compilerSpecId = requireText(root, "compilerSpecId", 32);
            long chipId = requireInteger(root, "chipId");
            if (!ESP32S3_TARGET.equals(targetId) || !ESP32S3_LANGUAGE.equals(languageId)
                || !"default".equals(compilerSpecId) || chipId != ESP32S3_CHIP_ID) {
                throw invalid("ESP32-S3 pilot descriptors require target esp32s3, chip 9, "
                    + "language " + ESP32S3_LANGUAGE + " with default compiler spec");
            }
            String optimization = requireText(root, "optimization", 8);
            requireMatches(OPTIMIZATION, optimization, "optimization");
            String idfVersion = requireText(root, "idfVersion", 64);
            requireMatches(GIT_REVISION, requireText(root, "idfRevision", 64), "idfRevision");
            String sdkconfigSha256 = requireDigest(root, "sdkconfigSha256");
            String referenceElfSha256 = requireDigest(root, "referenceElfSha256");
            String strippedImageSha256 = requireDigest(root, "strippedImageSha256");
            String fidbSha256 = requireDigest(root, "fidbSha256");
            long functionCount = requireInteger(root, "functionCount");
            if (functionCount < 1 || functionCount > limits.maxObjects()) {
                throw invalid("functionCount must be a positive bounded count");
            }
            String generatorCommand = requireText(root, "generatorCommand", 512);
            String ghidraVersion = requireText(root, "ghidraVersion", 32);
            requireMatches(VERSION, ghidraVersion, "ghidraVersion");
            List<Esp32S3FidComponent> components =
                parseComponents(root.get("components"), limits);
            RedistributionStatus redistribution = parseRedistribution(
                requireText(root, "redistribution", 16));
            return new Esp32S3FidProvenance(schemaId,
                requireText(root, "artifactId", 128), targetId, Math.toIntExact(chipId),
                languageId, compilerSpecId, idfVersion,
                requireText(root, "idfRevision", 64), requireText(root, "toolchain", 256),
                optimization, sdkconfigSha256, referenceElfSha256, strippedImageSha256,
                fidbSha256, Math.toIntExact(functionCount), generatorCommand, ghidraVersion,
                requireText(root, "libraryFamily", 128), requireText(root, "libraryVersion", 64),
                requireText(root, "libraryVariant", 64), components, redistribution);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid ESP32-S3 Function ID provenance: "
                + exception.getMessage());
        }
        catch (NullPointerException exception) {
            throw invalid("ESP32-S3 Function ID provenance is missing required values");
        }
    }

    public String identity() {
        return libraryFamily + "|" + libraryVersion + "|" + libraryVariant;
    }

    public boolean redistributionAllowed() {
        return redistribution == RedistributionStatus.ALLOWED;
    }

    private static List<Esp32S3FidComponent> parseComponents(Object value, ParserLimits limits)
            throws DiagnosticException {
        if (!(value instanceof List<?> entries) || entries.isEmpty()
            || entries.size() > limits.maxObjects()) {
            throw invalid("components must be a non-empty bounded array");
        }
        List<Esp32S3FidComponent> result = new ArrayList<>();
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> mapValue)) {
                throw invalid("Each component audit entry must be an object");
            }
            Map<String, Object> component = requireClosedKeys(castKeys(mapValue), COMPONENT_KEYS);
            RedistributionStatus status = parseRedistribution(
                requireText(component, "redistribution", 16));
            if (status == RedistributionStatus.PROHIBITED) {
                throw invalid("Prohibited components must not appear in a pilot descriptor");
            }
            result.add(new Esp32S3FidComponent(requireText(component, "name", 128),
                requireText(component, "license", 64), status));
        }
        return List.copyOf(result);
    }

    private static RedistributionStatus parseRedistribution(String value)
            throws DiagnosticException {
        RedistributionStatus status;
        try {
            status = RedistributionStatus.valueOf(value);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Unknown redistribution disposition: " + value);
        }
        if (status == RedistributionStatus.PROHIBITED) {
            throw invalid("Prohibited provenance must not be recorded as a pilot database");
        }
        return status;
    }

    private static Map<String, Object> requireClosedKeys(Map<String, Object> value,
            Set<String> allowed) throws DiagnosticException {
        for (String key : value.keySet()) {
            if (!allowed.contains(key)) {
                throw invalid("Unknown provenance key: " + key);
            }
        }
        return value;
    }

    private static Map<String, Object> castKeys(Map<?, ?> value) {
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : value.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("JSON object keys must be strings");
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static String requireText(Map<String, Object> value, String key, int maxLength)
            throws DiagnosticException {
        Object item = value.get(key);
        if (!(item instanceof String text) || text.isBlank() || text.length() > maxLength) {
            throw invalid("Provenance text field is missing, blank, or too long: " + key);
        }
        for (String marker : HOST_PATH_MARKERS) {
            if (text.contains(marker)) {
                throw invalid("Provenance field must not contain host paths: " + key);
            }
        }
        if (Pattern.compile("^[A-Za-z]:[\\\\/]").matcher(text).find()) {
            throw invalid("Provenance field must not contain drive-qualified paths: " + key);
        }
        return text;
    }

    private static String requireDigest(Map<String, Object> value, String key)
            throws DiagnosticException {
        String text = requireText(value, key, 64);
        requireMatches(SHA256, text, key);
        return text;
    }

    private static void requireMatches(Pattern pattern, String value, String key)
            throws DiagnosticException {
        if (!pattern.matcher(value).matches()) {
            throw invalid("Provenance field has an invalid form: " + key);
        }
    }

    private static long requireInteger(Map<String, Object> value, String key)
            throws DiagnosticException {
        Object item = value.get(key);
        if (!(item instanceof Long number)) {
            throw invalid("Provenance integer field is missing or not an integer: " + key);
        }
        return number;
    }

    private static DiagnosticException invalid(String message) {
        return new DiagnosticException(Diagnostic.error(
            DiagnosticCode.ESP_FID_PROVENANCE_INVALID, message, null));
    }
}
