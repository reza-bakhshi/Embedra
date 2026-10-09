package io.github.rezabakhshi.embedra.analyzers.plugins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScannerPluginRegistryTest {

    private ScannerPluginRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new ScannerPluginRegistry();
    }

    @AfterEach
    void tearDown() {
        registry.clear();
    }

    @Test
    void registersAndRetrievesPlugin() throws Exception {
        ScannerPlugin plugin = createDummyPlugin("test.p1", "ALL");
        registry.register(plugin);

        assertEquals(1, registry.allPlugins().size());
        assertEquals(plugin, registry.get("test.p1"));

        // Reject duplicate
        DiagnosticException ex = assertThrows(DiagnosticException.class, () -> registry.register(plugin));
        assertEquals(DiagnosticCode.PLUGIN_MANIFEST_INVALID, ex.diagnostic().code());

        assertTrue(registry.unregister("test.p1"));
        assertNull(registry.get("test.p1"));
        assertFalse(registry.unregister("test.p1"));
    }

    @Test
    void registersDeclarativePluginFromJson() throws Exception {
        String json = """
                {
                  "schemaId": "urn:embedra:schema:scanner-plugin-manifest:1",
                  "pluginId": "json.decl",
                  "name": "Declarative JSON Plugin",
                  "version": "1.0.0",
                  "author": "Embedra",
                  "description": "Test",
                  "pluginType": "DECLARATIVE_RULE",
                  "capabilities": ["BYTE_SCAN"],
                  "resourceLimits": {
                    "maxWallTimeMs": 2000,
                    "maxMemoryBytes": 1048576,
                    "maxFindings": 10
                  },
                  "declarativeRules": [
                    {
                      "ruleId": "r1",
                      "description": "desc",
                      "matcherType": "EXACT_STRING",
                      "pattern": "TARGET",
                      "severity": "INFO",
                      "confidence": "LEAD",
                      "confidenceScore": 0.5,
                      "secret": false
                    }
                  ]
                }
                """;

        ScannerPlugin plugin = registry.registerDeclarativePlugin(
                json, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(plugin);
        assertEquals("json.decl", plugin.manifest().pluginId());
        assertEquals(plugin, registry.get("json.decl"));
    }

    @Test
    void discoversPluginsInDirectory(@TempDir Path tempDir) throws Exception {
        Path p1 = tempDir.resolve("plugin1.json");
        Path p2 = tempDir.resolve("plugin2.json");
        Path txt = tempDir.resolve("not-a-plugin.txt");

        Files.writeString(p1, """
                {
                  "schemaId": "urn:embedra:schema:scanner-plugin-manifest:1",
                  "pluginId": "dir.p1",
                  "name": "P1",
                  "version": "1.0.0",
                  "author": "A",
                  "description": "D",
                  "pluginType": "DECLARATIVE_RULE",
                  "capabilities": ["BYTE_SCAN"],
                  "resourceLimits": {"maxWallTimeMs": 1000, "maxMemoryBytes": 1048576, "maxFindings": 10},
                  "declarativeRules": [{"ruleId": "r1", "description": "d", "matcherType": "EXACT_STRING",
                    "pattern": "A", "severity": "INFO", "confidence": "LEAD", "confidenceScore": 0.5, "secret": false}]
                }
                """);

        Files.writeString(p2, """
                {
                  "schemaId": "urn:embedra:schema:scanner-plugin-manifest:1",
                  "pluginId": "dir.p2",
                  "name": "P2",
                  "version": "1.0.0",
                  "author": "A",
                  "description": "D",
                  "pluginType": "DECLARATIVE_RULE",
                  "capabilities": ["BYTE_SCAN"],
                  "resourceLimits": {"maxWallTimeMs": 1000, "maxMemoryBytes": 1048576, "maxFindings": 10},
                  "declarativeRules": [{"ruleId": "r2", "description": "d", "matcherType": "EXACT_STRING",
                    "pattern": "B", "severity": "INFO", "confidence": "LEAD", "confidenceScore": 0.5, "secret": false}]
                }
                """);

        Files.writeString(txt, "ignored");

        int discovered = registry.discoverPluginsInDirectory(
                tempDir, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(2, discovered);
        assertEquals(2, registry.allPlugins().size());
        assertNotNull(registry.get("dir.p1"));
        assertNotNull(registry.get("dir.p2"));
    }

    @Test
    void filtersExecutionByTargetPlatform() throws Exception {
        ScannerPlugin espPlugin = createDummyPlugin("esp.plugin", "ESP32");
        ScannerPlugin armPlugin = createDummyPlugin("arm.plugin", "ARM");
        ScannerPlugin allPlugin = createDummyPlugin("all.plugin", "ALL");

        registry.register(espPlugin);
        registry.register(armPlugin);
        registry.register(allPlugin);

        PluginScanContext context = new PluginScanContext(
                new byte[] {1, 2, 3},
                0L,
                List.of(),
                Map.of(),
                "ESP32",
                PluginResourceBudget.defaults(),
                CancellationToken.none()
        );

        ScannerPluginBatchReport report = registry.executeAll(context);

        assertEquals(2, report.results().size());
        List<String> executed = report.results().stream().map(ScannerPluginExecutionResult::pluginId).toList();
        assertTrue(executed.contains("esp.plugin"));
        assertTrue(executed.contains("all.plugin"));
        assertFalse(executed.contains("arm.plugin"));
    }

    private static ScannerPlugin createDummyPlugin(String id, String platform) {
        ScannerPluginManifest manifest = new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                id,
                "Dummy",
                "1.0.0",
                "Tester",
                "Description",
                PluginType.DECLARATIVE_RULE,
                platform,
                null,
                Set.of(PluginCapability.BYTE_SCAN),
                PluginResourceBudget.defaults(),
                List.of(new DeclarativeRuleDefinition(
                        "r1", "desc", DeclarativeMatcherType.EXACT_STRING, "pat",
                        FindingSeverity.INFO, FindingConfidence.LEAD, 0.5, false,
                        FindingCategory.CUSTOM_PLUGIN, "SUB", null, null))
        );
        return new DeclarativeScannerPlugin(manifest);
    }
}
