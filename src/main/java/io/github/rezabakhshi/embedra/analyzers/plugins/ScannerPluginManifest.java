package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Immutable, schema-validated manifest for a local scanner plugin (AN-009).
 */
public record ScannerPluginManifest(
        String schemaId,
        String pluginId,
        String name,
        String version,
        String author,
        String description,
        PluginType pluginType,
        String targetPlatform,
        String entryPoint,
        Set<PluginCapability> capabilities,
        PluginResourceBudget resourceLimits,
        List<DeclarativeRuleDefinition> declarativeRules) {

    public static final String SCHEMA_ID = "urn:embedra:schema:scanner-plugin-manifest:1";

    private static final Pattern PLUGIN_ID_PATTERN = Pattern.compile("^[a-z0-9]+(?:[.-][a-z0-9]+)*$");

    private static final Pattern VERSION_PATTERN = Pattern.compile(
            "^(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$");

    private static final Set<String> ALLOWED_ROOT_FIELDS = Set.of(
            "schemaId", "pluginId", "name", "version", "author", "description",
            "pluginType", "targetPlatform", "entryPoint", "capabilities",
            "resourceLimits", "declarativeRules"
    );

    private static final Set<String> ALLOWED_LIMIT_FIELDS = Set.of(
            "maxWallTimeMs", "maxMemoryBytes", "maxFindings"
    );

    private static final Set<String> ALLOWED_RULE_FIELDS = Set.of(
            "ruleId", "description", "matcherType", "pattern", "severity",
            "confidence", "confidenceScore", "secret", "category",
            "subcategory", "minEntropy", "maxEntropy"
    );

    public ScannerPluginManifest {
        Objects.requireNonNull(schemaId, "schemaId must not be null");
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new IllegalArgumentException("Unsupported schema ID: " + schemaId);
        }
        Objects.requireNonNull(pluginId, "pluginId must not be null");
        if (!PLUGIN_ID_PATTERN.matcher(pluginId).matches()) {
            throw new IllegalArgumentException("Invalid plugin ID format: " + pluginId);
        }
        Objects.requireNonNull(name, "name must not be null");
        if (name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        Objects.requireNonNull(version, "version must not be null");
        if (!VERSION_PATTERN.matcher(version).matches()) {
            throw new IllegalArgumentException("Invalid semver version format: " + version);
        }
        Objects.requireNonNull(author, "author must not be null");
        Objects.requireNonNull(description, "description must not be null");
        Objects.requireNonNull(pluginType, "pluginType must not be null");
        targetPlatform = (targetPlatform == null || targetPlatform.isBlank()) ? "ALL" : targetPlatform;
        if (entryPoint != null) {
            validatePathSafety(entryPoint);
        }
        if (capabilities == null || capabilities.isEmpty()) {
            throw new IllegalArgumentException("capabilities must be non-empty");
        }
        capabilities = Collections.unmodifiableSet(new LinkedHashSet<>(capabilities));
        Objects.requireNonNull(resourceLimits, "resourceLimits must not be null");
        declarativeRules = declarativeRules == null ? List.of() : List.copyOf(declarativeRules);
        if (pluginType == PluginType.DECLARATIVE_RULE && declarativeRules.isEmpty()) {
            throw new IllegalArgumentException("declarativeRules must not be empty for DECLARATIVE_RULE plugins");
        }
    }

    /**
     * Parses and validates a scanner plugin manifest from a JSON string.
     */
    public static ScannerPluginManifest parse(
            String json,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(json, "json must not be null");
        return parse(json.getBytes(StandardCharsets.UTF_8), limits, token);
    }

    /**
     * Parses and validates a scanner plugin manifest from UTF-8 bytes.
     */
    public static ScannerPluginManifest parse(
            byte[] bytes,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(bytes, "bytes must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        Object parsed = PluginManifestJsonParser.parse(bytes, limits, token);
        Map<String, Object> root = requireMap(parsed, "Plugin manifest root must be a JSON object");

        requireExactFields(root, ALLOWED_ROOT_FIELDS);

        String schemaId = requireString(root, "schemaId");
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_SCHEMA_UNSUPPORTED,
                    "Unsupported plugin schema ID: " + schemaId, null));
        }

        String pluginId = requireString(root, "pluginId");
        String name = requireString(root, "name");
        String version = requireString(root, "version");
        String author = requireString(root, "author");
        String description = requireString(root, "description");
        String typeStr = requireString(root, "pluginType");

        PluginType pluginType;
        try {
            pluginType = PluginType.valueOf(typeStr);
        } catch (IllegalArgumentException e) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Invalid pluginType: " + typeStr, null));
        }

        String targetPlatform = root.containsKey("targetPlatform")
                ? requireString(root, "targetPlatform") : "ALL";

        String entryPoint = root.containsKey("entryPoint")
                ? requireString(root, "entryPoint") : null;

        if (entryPoint != null) {
            try {
                validatePathSafety(entryPoint);
            } catch (IllegalArgumentException e) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PLUGIN_PATH_UNSAFE, e.getMessage(), null));
            }
        }

        Set<PluginCapability> capabilities = parseCapabilities(root.get("capabilities"));
        PluginResourceBudget budget = parseResourceLimits(root.get("resourceLimits"));

        List<DeclarativeRuleDefinition> rules = List.of();
        if (root.containsKey("declarativeRules")) {
            rules = parseDeclarativeRules(root.get("declarativeRules"));
        }

        try {
            return new ScannerPluginManifest(
                    schemaId, pluginId, name, version, author, description,
                    pluginType, targetPlatform, entryPoint, capabilities, budget, rules
            );
        } catch (IllegalArgumentException e) {
            DiagnosticCode code = e.getMessage() != null && e.getMessage().contains("path")
                    ? DiagnosticCode.PLUGIN_PATH_UNSAFE : DiagnosticCode.PLUGIN_MANIFEST_INVALID;
            throw new DiagnosticException(Diagnostic.error(code, e.getMessage(), null));
        }
    }

    private static void validatePathSafety(String path) {
        if (path.startsWith("/") || path.startsWith("\\")
                || path.contains("../") || path.contains("..\\")
                || path.equals("..") || path.contains("\0")) {
            throw new IllegalArgumentException("Entry point path is unsafe or contains traversal: " + path);
        }
    }

    private static Set<PluginCapability> parseCapabilities(Object obj) throws DiagnosticException {
        if (!(obj instanceof List<?> list) || list.isEmpty()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID, "capabilities must be a non-empty array", null));
        }
        Set<PluginCapability> caps = new LinkedHashSet<>();
        for (Object item : list) {
            if (!(item instanceof String s)) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PLUGIN_MANIFEST_INVALID, "capabilities items must be strings", null));
            }
            try {
                caps.add(PluginCapability.valueOf(s));
            } catch (IllegalArgumentException e) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Unknown capability: " + s, null));
            }
        }
        return caps;
    }

    private static PluginResourceBudget parseResourceLimits(Object obj) throws DiagnosticException {
        Map<String, Object> map = requireMap(obj, "resourceLimits must be an object");
        requireExactFields(map, ALLOWED_LIMIT_FIELDS);

        long wallTime = requireLong(map, "maxWallTimeMs");
        long memory = requireLong(map, "maxMemoryBytes");
        long findings = requireLong(map, "maxFindings");

        try {
            return new PluginResourceBudget(wallTime, memory, (int) findings);
        } catch (IllegalArgumentException e) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Invalid resource limits: " + e.getMessage(), null));
        }
    }

    private static List<DeclarativeRuleDefinition> parseDeclarativeRules(Object obj) throws DiagnosticException {
        if (!(obj instanceof List<?> list)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID, "declarativeRules must be an array", null));
        }
        List<DeclarativeRuleDefinition> rules = new ArrayList<>();
        for (Object item : list) {
            Map<String, Object> map = requireMap(item, "declarativeRule entry must be an object");
            for (String key : map.keySet()) {
                if (!ALLOWED_RULE_FIELDS.contains(key)) {
                    throw new DiagnosticException(Diagnostic.error(
                            DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Unknown rule field: " + key, null));
                }
            }

            String ruleId = requireString(map, "ruleId");
            String desc = requireString(map, "description");
            DeclarativeMatcherType matcherType;
            try {
                matcherType = DeclarativeMatcherType.valueOf(requireString(map, "matcherType"));
            } catch (IllegalArgumentException e) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PLUGIN_MANIFEST_INVALID,
                        "Invalid matcherType: " + map.get("matcherType"), null));
            }
            String pattern = map.containsKey("pattern") ? requireString(map, "pattern") : "";
            FindingSeverity severity = FindingSeverity.valueOf(requireString(map, "severity"));
            FindingConfidence confidence = FindingConfidence.valueOf(requireString(map, "confidence"));
            double score = requireDouble(map, "confidenceScore");
            boolean secret = requireBoolean(map, "secret");

            FindingCategory category = map.containsKey("category")
                    ? FindingCategory.valueOf(requireString(map, "category")) : FindingCategory.CUSTOM_PLUGIN;
            String subcategory = map.containsKey("subcategory")
                    ? requireString(map, "subcategory") : ruleId;
            Double minEntropy = map.containsKey("minEntropy")
                    ? requireDouble(map, "minEntropy") : null;
            Double maxEntropy = map.containsKey("maxEntropy")
                    ? requireDouble(map, "maxEntropy") : null;

            try {
                rules.add(new DeclarativeRuleDefinition(
                        ruleId, desc, matcherType, pattern, severity, confidence,
                        score, secret, category, subcategory, minEntropy, maxEntropy
                ));
            } catch (IllegalArgumentException e) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Invalid declarative rule: " + e.getMessage(), null));
            }
        }
        return rules;
    }

    private static void requireExactFields(Map<String, Object> map, Set<String> allowed) throws DiagnosticException {
        for (String key : map.keySet()) {
            if (!allowed.contains(key)) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PLUGIN_MANIFEST_INVALID,
                        "Unknown field in plugin manifest: " + key, null));
            }
        }
    }

    private static Map<String, Object> requireMap(Object value, String message) throws DiagnosticException {
        if (!(value instanceof Map<?, ?> untyped)) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.PLUGIN_MANIFEST_INVALID, message, null));
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : untyped.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PLUGIN_MANIFEST_INVALID, message, null));
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static String requireString(Map<String, Object> map, String key) throws DiagnosticException {
        Object val = map.get(key);
        if (!(val instanceof String s) || s.isBlank()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Field '" + key + "' must be a non-empty string", null));
        }
        return s;
    }

    private static long requireLong(Map<String, Object> map, String key) throws DiagnosticException {
        Object val = map.get(key);
        if (!(val instanceof Long l)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Field '" + key + "' must be an integer", null));
        }
        return l;
    }

    private static double requireDouble(Map<String, Object> map, String key) throws DiagnosticException {
        Object val = map.get(key);
        if (val instanceof Double d) {
            return d;
        }
        if (val instanceof Long l) {
            return l.doubleValue();
        }
        throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Field '" + key + "' must be a number", null));
    }

    private static boolean requireBoolean(Map<String, Object> map, String key) throws DiagnosticException {
        Object val = map.get(key);
        if (!(val instanceof Boolean b)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID, "Field '" + key + "' must be a boolean", null));
        }
        return b;
    }
}
