package io.github.rezabakhshi.embedra.analyzers.plugins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ScannerPluginManifestTest {

    private static final String VALID_MANIFEST = """
            {
              "schemaId": "urn:embedra:schema:scanner-plugin-manifest:1",
              "pluginId": "custom.crypto-key-detector",
              "name": "Custom Crypto Key Detector",
              "version": "1.0.0",
              "author": "Embedra Team",
              "description": "Identifies proprietary AES keys and canary tokens",
              "pluginType": "DECLARATIVE_RULE",
              "targetPlatform": "ESP32",
              "capabilities": ["BYTE_SCAN", "STRING_SCAN"],
              "resourceLimits": {
                "maxWallTimeMs": 2000,
                "maxMemoryBytes": 8388608,
                "maxFindings": 100
              },
              "declarativeRules": [
                {
                  "ruleId": "aes-key-canary",
                  "description": "Candidate proprietary AES key",
                  "matcherType": "HEX_BYTES",
                  "pattern": "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff",
                  "severity": "HIGH",
                  "confidence": "LIKELY",
                  "confidenceScore": 0.85,
                  "secret": true,
                  "category": "CRYPTOGRAPHY",
                  "subcategory": "AES_KEY"
                }
              ]
            }
            """;

    @Test
    void parsesValidDeclarativeManifestSuccessfully() throws DiagnosticException {
        ScannerPluginManifest manifest = ScannerPluginManifest.parse(
                VALID_MANIFEST, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(manifest);
        assertEquals(ScannerPluginManifest.SCHEMA_ID, manifest.schemaId());
        assertEquals("custom.crypto-key-detector", manifest.pluginId());
        assertEquals("Custom Crypto Key Detector", manifest.name());
        assertEquals("1.0.0", manifest.version());
        assertEquals("Embedra Team", manifest.author());
        assertEquals(PluginType.DECLARATIVE_RULE, manifest.pluginType());
        assertEquals("ESP32", manifest.targetPlatform());
        assertEquals(Set.of(PluginCapability.BYTE_SCAN, PluginCapability.STRING_SCAN), manifest.capabilities());
        assertEquals(2000L, manifest.resourceLimits().maxWallTimeMs());
        assertEquals(100, manifest.resourceLimits().maxFindings());
        assertEquals(1, manifest.declarativeRules().size());

        DeclarativeRuleDefinition rule = manifest.declarativeRules().get(0);
        assertEquals("aes-key-canary", rule.ruleId());
        assertEquals(DeclarativeMatcherType.HEX_BYTES, rule.matcherType());
        assertEquals(FindingSeverity.HIGH, rule.severity());
        assertEquals(FindingConfidence.LIKELY, rule.confidence());
        assertEquals(0.85, rule.confidenceScore(), 0.001);
        assertTrue(rule.secret());
        assertEquals(FindingCategory.CRYPTOGRAPHY, rule.category());
        assertEquals("AES_KEY", rule.subcategory());
    }

    @Test
    void rejectsUnsupportedSchemaId() {
        String invalid = VALID_MANIFEST.replace(
                "urn:embedra:schema:scanner-plugin-manifest:1",
                "urn:embedra:schema:scanner-plugin-manifest:99");

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                ScannerPluginManifest.parse(invalid, ParserLimits.defaults(), CancellationToken.none()));

        assertEquals(DiagnosticCode.PLUGIN_SCHEMA_UNSUPPORTED, ex.diagnostic().code());
    }

    @Test
    void rejectsUnknownExtraFields() {
        String invalid = VALID_MANIFEST.replace(
                "\"author\": \"Embedra Team\",",
                "\"author\": \"Embedra Team\", \"maliciousField\": \"injected\",");

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                ScannerPluginManifest.parse(invalid, ParserLimits.defaults(), CancellationToken.none()));

        assertEquals(DiagnosticCode.PLUGIN_MANIFEST_INVALID, ex.diagnostic().code());
    }

    @Test
    void rejectsUnsafePathTraversalInEntryPoint() {
        String invalid = """
                {
                  "schemaId": "urn:embedra:schema:scanner-plugin-manifest:1",
                  "pluginId": "malicious.traversal",
                  "name": "Malicious Traversal",
                  "version": "1.0.0",
                  "author": "Attacker",
                  "description": "Traversal attempt",
                  "pluginType": "JAVA_CLASS",
                  "entryPoint": "../../../etc/passwd",
                  "capabilities": ["BYTE_SCAN"],
                  "resourceLimits": {
                    "maxWallTimeMs": 1000,
                    "maxMemoryBytes": 1048576,
                    "maxFindings": 10
                  }
                }
                """;

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                ScannerPluginManifest.parse(invalid, ParserLimits.defaults(), CancellationToken.none()));

        assertEquals(DiagnosticCode.PLUGIN_PATH_UNSAFE, ex.diagnostic().code());
    }

    @Test
    void rejectsAbsoluteEntryPointPath() {
        String invalid = """
                {
                  "schemaId": "urn:embedra:schema:scanner-plugin-manifest:1",
                  "pluginId": "malicious.absolute",
                  "name": "Absolute Path",
                  "version": "1.0.0",
                  "author": "Attacker",
                  "description": "Absolute path",
                  "pluginType": "JAVA_CLASS",
                  "entryPoint": "/opt/payload.jar",
                  "capabilities": ["BYTE_SCAN"],
                  "resourceLimits": {
                    "maxWallTimeMs": 1000,
                    "maxMemoryBytes": 1048576,
                    "maxFindings": 10
                  }
                }
                """;

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                ScannerPluginManifest.parse(invalid, ParserLimits.defaults(), CancellationToken.none()));

        assertEquals(DiagnosticCode.PLUGIN_PATH_UNSAFE, ex.diagnostic().code());
    }

    @Test
    void rejectsInvalidVersionFormat() {
        String invalid = VALID_MANIFEST.replace("\"version\": \"1.0.0\",", "\"version\": \"1.0.alpha\",");

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                ScannerPluginManifest.parse(invalid, ParserLimits.defaults(), CancellationToken.none()));

        assertEquals(DiagnosticCode.PLUGIN_MANIFEST_INVALID, ex.diagnostic().code());
    }

    @Test
    void rejectsOutOfRangeResourceLimits() {
        String invalidWallTime = VALID_MANIFEST.replace("\"maxWallTimeMs\": 2000,", "\"maxWallTimeMs\": 2,");

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                ScannerPluginManifest.parse(invalidWallTime, ParserLimits.defaults(), CancellationToken.none()));

        assertEquals(DiagnosticCode.PLUGIN_MANIFEST_INVALID, ex.diagnostic().code());
    }

    @Test
    void rejectsEmptyDeclarativeRulesForDeclarativeType() {
        String invalid = """
                {
                  "schemaId": "urn:embedra:schema:scanner-plugin-manifest:1",
                  "pluginId": "empty.rules",
                  "name": "Empty Rules",
                  "version": "1.0.0",
                  "author": "Test",
                  "description": "Empty rules",
                  "pluginType": "DECLARATIVE_RULE",
                  "capabilities": ["BYTE_SCAN"],
                  "resourceLimits": {
                    "maxWallTimeMs": 1000,
                    "maxMemoryBytes": 1048576,
                    "maxFindings": 10
                  },
                  "declarativeRules": []
                }
                """;

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                ScannerPluginManifest.parse(invalid, ParserLimits.defaults(), CancellationToken.none()));

        assertEquals(DiagnosticCode.PLUGIN_MANIFEST_INVALID, ex.diagnostic().code());
    }
}
