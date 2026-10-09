package io.github.rezabakhshi.embedra.core.report;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.pack.PackManifest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SchemaResourcesTest {
    private static final Path PROJECT = Path.of(System.getProperty("embedra.projectDir"));

    @Test
    void versionedSchemasAreCheckedInAndClosed() throws IOException {
        Map<String, String> schemas = Map.of(
            "schemas/report/canonical-report-v1.schema.json", CanonicalReport.SCHEMA_ID,
            "schemas/report/execution-topology-v1.schema.json", ExecutionTopologyReport.SCHEMA_ID,
            "schemas/catalog/device-catalog-snapshot-v1.schema.json",
                "urn:embedra:schema:device-catalog-snapshot:1",
            "schemas/catalog/device-catalog-diff-v1.schema.json",
                "urn:embedra:schema:device-catalog-diff:1",
            "schemas/catalog/esp-device-catalog-v1.schema.json",
                "urn:embedra:schema:esp-device-catalog:1",
            "schemas/pack/pack-manifest-v1.schema.json", PackManifest.SCHEMA_ID,
            "schemas/plugin/scanner-plugin-manifest-v1.schema.json",
                "urn:embedra:schema:scanner-plugin-manifest:1",
            "schemas/crypto/crypto-signature-pack-v1.schema.json",
                "urn:embedra:schema:crypto-signature-pack:1");

        for (Map.Entry<String, String> schema : schemas.entrySet()) {
            String text = Files.readString(PROJECT.resolve(schema.getKey()), StandardCharsets.UTF_8);
            assertTrue(text.startsWith("{\n"), schema.getKey());
            assertTrue(text.endsWith("}\n"), schema.getKey());
            assertTrue(text.contains("\"$id\": \"" + schema.getValue() + "\""), schema.getKey());
            assertTrue(text.contains("\"additionalProperties\": false"), schema.getKey());
            assertNotNull(getClass().getClassLoader().getResource(schema.getKey()), schema.getKey());
        }
    }
}
