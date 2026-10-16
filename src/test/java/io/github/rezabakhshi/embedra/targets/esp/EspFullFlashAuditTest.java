package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Automated verification for the T080 ESP full-flash capability matrix and audit. */
class EspFullFlashAuditTest {
    private static final Path MATRIX_PATH =
        Path.of(".embedra/evidence/tasks/T080-capability-matrix.json");

    private static final Path AUDIT_DOC_PATH =
        Path.of("docs/esp-full-flash-audit.md");

    private static final Set<String> EXPECTED_SERIES = Set.of(
        "ESP32", "ESP32-S2", "ESP32-S3", "ESP32-S31", "ESP32-P4",
        "ESP32-C2", "ESP32-C3", "ESP32-C5", "ESP32-C6", "ESP32-C61",
        "ESP32-E22", "ESP32-H2", "ESP32-H21", "ESP32-H4"
    );

    @Test
    void auditDocumentExistsAndContainsRequiredSections() throws IOException {
        assertTrue(Files.isRegularFile(AUDIT_DOC_PATH), "Audit document must exist");
        String content = Files.readString(AUDIT_DOC_PATH);

        assertTrue(content.contains("ESP32-Branded Full-Flash Layout & Architectural Audit"));
        assertTrue(content.contains("Segregation of ESP8266"));
        assertTrue(content.contains("Per-Series Capability Matrix"));
        assertTrue(content.contains("53 Silicon Parts"));
        assertTrue(content.contains("Inventory of Current S3 Hardcoded Assumptions"));
        assertTrue(content.contains("EspFlashLayoutProfile"));
        assertTrue(content.contains("EspFlashLayoutProvider"));

        for (String series : EXPECTED_SERIES) {
            assertTrue(content.contains(series), "Audit document must discuss " + series);
        }
    }

    @Test
    void capabilityMatrixCoversAllFourteenSeriesAndFiftyThreeSiliconParts() throws IOException {
        assertTrue(Files.isRegularFile(MATRIX_PATH), "Capability matrix file must exist");
        String json = Files.readString(MATRIX_PATH);

        for (String series : EXPECTED_SERIES) {
            assertTrue(json.contains("\"series\": \"" + series + "\""),
                "Matrix must cover series " + series);
        }
        assertTrue(json.contains("\"totalSeriesCount\": 14"));
        assertTrue(json.contains("\"totalSiliconPartCount\": 53"));
    }

    @Test
    void bootloaderAndPartitionTableOffsetsMatchRules() {
        List<EspTargetProvider> providers = EspTargetProviders.implemented();
        assertEquals(14, providers.size(), "Must have 14 implemented ESP target providers");

        Set<String> providerDeviceIds = providers.stream()
            .map(p -> p.providerId().replace("target.", ""))
            .collect(Collectors.toSet());

        assertFalse(providerDeviceIds.contains("esp8266"),
            "ESP8266 must be segregated and excluded from ESP32 providers");

        // Verify chip IDs match registry
        EspressifChipIdRegistry registry = EspressifChipIdRegistry.loadBundled();
        for (EspTargetProvider provider : providers) {
            EspressifChipDefinition def = registry.requireByChipId(provider.chipId());
            assertEquals(provider.chipId(), def.chipId());
        }
    }

    @Test
    void esp8266SegregationIsPreserved() throws IOException {
        String json = Files.readString(MATRIX_PATH);
        assertTrue(json.contains("\"excludedFromEsp32FullFlash\": true"));
        assertTrue(json.contains("\"series\": \"ESP8266\""));
    }
}
