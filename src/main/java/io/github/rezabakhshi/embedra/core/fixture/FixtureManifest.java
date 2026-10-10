package io.github.rezabakhshi.embedra.core.fixture;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.report.CanonicalJson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Immutable, schema-validated manifest for test and acceptance fixtures (SPEC-12, AN-015).
 */
public record FixtureManifest(
        String schemaId,
        String fixtureId,
        String sha256,
        String target,
        String device,
        String inputFormat,
        String origin,
        String license,
        RedistributionStatus redistributionStatus,
        Object sourceProvenance,
        String generatorRevision,
        String generationCommand,
        String toolchain,
        List<String> oracleCommands,
        String expectedSnapshot,
        List<String> requirements,
        Boolean malformed,
        String scriptRevision,
        Boolean privateDigestOnly) {

    public static final String SCHEMA_ID = "urn:embedra:schema:fixture-manifest:1";

    private static final Pattern SHA256_PATTERN = Pattern.compile("^[0-9a-f]{64}$");

    public FixtureManifest {
        Objects.requireNonNull(fixtureId, "fixtureId");
        if (fixtureId.isBlank()) {
            throw new IllegalArgumentException("fixtureId must not be blank");
        }
        if (fixtureId.contains("..") || fixtureId.contains("/") || fixtureId.contains("\\")) {
            throw new IllegalArgumentException("fixtureId contains unsafe path characters");
        }
        Objects.requireNonNull(sha256, "sha256");
        if (!SHA256_PATTERN.matcher(sha256).matches()) {
            throw new IllegalArgumentException("sha256 must be a 64-hex lowercase digest: " + sha256);
        }
        Objects.requireNonNull(target, "target");
        if (target.isBlank()) {
            throw new IllegalArgumentException("target must not be blank");
        }
        Objects.requireNonNull(inputFormat, "inputFormat");
        if (inputFormat.isBlank()) {
            throw new IllegalArgumentException("inputFormat must not be blank");
        }
        Objects.requireNonNull(origin, "origin");
        if (origin.isBlank()) {
            throw new IllegalArgumentException("origin must not be blank");
        }
        Objects.requireNonNull(license, "license");
        if (license.isBlank()) {
            throw new IllegalArgumentException("license must not be blank");
        }
        Objects.requireNonNull(redistributionStatus, "redistributionStatus");
        Objects.requireNonNull(generatorRevision, "generatorRevision");
        if (generatorRevision.isBlank()) {
            throw new IllegalArgumentException("generatorRevision must not be blank");
        }
        Objects.requireNonNull(generationCommand, "generationCommand");
        if (generationCommand.isBlank()) {
            throw new IllegalArgumentException("generationCommand must not be blank");
        }
        Objects.requireNonNull(toolchain, "toolchain");
        if (toolchain.isBlank()) {
            throw new IllegalArgumentException("toolchain must not be blank");
        }
        Objects.requireNonNull(oracleCommands, "oracleCommands");
        if (oracleCommands.isEmpty()) {
            throw new IllegalArgumentException("oracleCommands must not be empty");
        }
        oracleCommands = List.copyOf(oracleCommands);

        Objects.requireNonNull(expectedSnapshot, "expectedSnapshot");
        if (expectedSnapshot.isBlank()) {
            throw new IllegalArgumentException("expectedSnapshot must not be blank");
        }
        if (expectedSnapshot.contains("..") || expectedSnapshot.startsWith("/")
                || expectedSnapshot.contains("\\")) {
            throw new IllegalArgumentException("expectedSnapshot contains unsafe path traversal");
        }

        Objects.requireNonNull(requirements, "requirements");
        if (requirements.isEmpty()) {
            throw new IllegalArgumentException("requirements must not be empty");
        }
        List<String> sortedReqs = new ArrayList<>(requirements);
        Collections.sort(sortedReqs);
        requirements = List.copyOf(sortedReqs);
    }

    public static FixtureManifest parse(
            byte[] bytes,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Object parsed = FixtureManifestJsonParser.parse(bytes, limits, token);
        if (!(parsed instanceof Map<?, ?> map)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_MANIFEST_INVALID,
                    "Fixture manifest root must be a JSON object"));
        }
        return fromMap(map);
    }

    public static FixtureManifest parse(
            String text,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        return parse(text.getBytes(java.nio.charset.StandardCharsets.UTF_8), limits, token);
    }

    public static FixtureManifest read(
            Path path,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException, IOException {
        if (!Files.isRegularFile(path) || Files.isSymbolicLink(path)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_PATH_UNSAFE,
                    "Fixture manifest is missing or a symbolic link: " + path));
        }
        byte[] bytes = Files.readAllBytes(path);
        return parse(bytes, limits, token);
    }

    @SuppressWarnings("unchecked")
    public static FixtureManifest fromMap(Map<?, ?> map) throws DiagnosticException {
        try {
            String schemaId = map.get("schemaId") instanceof String s ? s : SCHEMA_ID;
            String fixtureId = requireString(map, "fixtureId");
            String sha256 = requireString(map, "sha256");
            String target = requireString(map, "target");
            String device = map.get("device") instanceof String d ? d : null;
            String inputFormat = requireString(map, "inputFormat");
            String origin = requireString(map, "origin");
            String license = requireString(map, "license");
            String redistStr = requireString(map, "redistributionStatus");
            RedistributionStatus redist = RedistributionStatus.parse(redistStr);

            Object sourceProv = map.get("sourceProvenance");
            String generatorRevision = requireString(map, "generatorRevision");
            String generationCommand = requireString(map, "generationCommand");
            String toolchain = requireString(map, "toolchain");

            List<String> oracleCommands = parseStringList(map.get("oracleCommands"), "oracleCommands");
            String expectedSnapshot = requireString(map, "expectedSnapshot");
            List<String> requirements = parseStringList(map.get("requirements"), "requirements");

            Boolean malformed = map.get("malformed") instanceof Boolean b ? b : null;
            String scriptRevision = map.get("scriptRevision") instanceof String sr ? sr : null;
            Boolean privateDigestOnly = map.get("privateDigestOnly") instanceof Boolean p ? p : null;

            return new FixtureManifest(
                    schemaId,
                    fixtureId,
                    sha256,
                    target,
                    device,
                    inputFormat,
                    origin,
                    license,
                    redist,
                    sourceProv,
                    generatorRevision,
                    generationCommand,
                    toolchain,
                    oracleCommands,
                    expectedSnapshot,
                    requirements,
                    malformed,
                    scriptRevision,
                    privateDigestOnly);
        } catch (IllegalArgumentException exception) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_MANIFEST_INVALID,
                    "Invalid fixture manifest: " + exception.getMessage()));
        }
    }

    public void validateFixtureBinary(Path fixtureFile) throws DiagnosticException, IOException {
        if (!Files.exists(fixtureFile)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_PATH_UNSAFE,
                    "Fixture file does not exist: " + fixtureFile));
        }
        if (Files.isSymbolicLink(fixtureFile)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_PATH_UNSAFE,
                    "Fixture file must not be a symbolic link: " + fixtureFile));
        }
        if (!Files.isRegularFile(fixtureFile)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_PATH_UNSAFE,
                    "Fixture file must be a regular file: " + fixtureFile));
        }

        byte[] bytes = Files.readAllBytes(fixtureFile);
        String actualSha256 = computeSha256(bytes);
        if (!actualSha256.equalsIgnoreCase(sha256)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_INTEGRITY_MISMATCH,
                    "Fixture digest mismatch for " + fixtureId + ": expected " + sha256 + ", got " + actualSha256));
        }
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("fixtureId", fixtureId);
        map.put("sha256", sha256);
        map.put("target", target);
        if (device != null) {
            map.put("device", device);
        }
        map.put("inputFormat", inputFormat);
        map.put("origin", origin);
        map.put("license", license);
        map.put("redistributionStatus", redistributionStatus.id());
        if (sourceProvenance != null) {
            map.put("sourceProvenance", sourceProvenance);
        }
        map.put("generatorRevision", generatorRevision);
        map.put("generationCommand", generationCommand);
        map.put("toolchain", toolchain);
        map.put("oracleCommands", oracleCommands);
        map.put("expectedSnapshot", expectedSnapshot);
        map.put("requirements", requirements);
        if (malformed != null) {
            map.put("malformed", malformed);
        }
        if (scriptRevision != null) {
            map.put("scriptRevision", scriptRevision);
        }
        if (privateDigestOnly != null) {
            map.put("privateDigestOnly", privateDigestOnly);
        }
        return map;
    }

    public String toJson() {
        return CanonicalJson.write(toMap());
    }

    public static String computeSha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(data));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 not available", exception);
        }
    }

    private static String requireString(Map<?, ?> map, String key) {
        Object val = map.get(key);
        if (val instanceof String s && !s.isBlank()) {
            return s;
        }
        throw new IllegalArgumentException("Missing or blank string field: " + key);
    }

    private static List<String> parseStringList(Object obj, String fieldName) {
        if (!(obj instanceof List<?> list) || list.isEmpty()) {
            throw new IllegalArgumentException("Field " + fieldName + " must be a non-empty list");
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof String s && !s.isBlank()) {
                result.add(s);
            } else {
                throw new IllegalArgumentException("Field " + fieldName + " must contain non-blank strings");
            }
        }
        return result;
    }
}
