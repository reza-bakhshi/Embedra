package io.github.rezabakhshi.embedra.targets.stm8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Automated verification for the T088 STM8 capability matrix and technical audit. */
class Stm8AuditTest {
    private static final Path MATRIX_PATH =
        Path.of(".embedra/evidence/tasks/T088-stm8-capability-matrix.json");

    private static final Path AUDIT_DOC_PATH =
        Path.of("docs/stm8-audit.md");

    private static final Set<String> EXPECTED_FAMILIES = Set.of(
        "STM8S", "STM8L", "STM8A", "STM8T"
    );

    @Test
    void auditDocumentExistsAndContainsRequiredSections() throws IOException {
        assertTrue(Files.isRegularFile(AUDIT_DOC_PATH), "Audit document must exist");
        String content = Files.readString(AUDIT_DOC_PATH);

        assertTrue(content.contains("STM8 8-Bit MCU Family Layout, Vector & Architectural Audit"));
        assertTrue(content.contains("Scope and Pinned Authoritative Baselines"));
        assertTrue(content.contains("Documentation Provenance & License Analysis"));
        assertTrue(content.contains("CPU Core Architecture & Execution Model"));
        assertTrue(content.contains("Unified Linear Memory Map & Invariants"));
        assertTrue(content.contains("Interrupt Vector Table Architecture"));
        assertTrue(content.contains("Curated Exact-Part Allowlist (32 Silicon Parts)"));
        assertTrue(content.contains("Ghidra Language Binding Specification"));
        assertTrue(content.contains("Strict Segregation from STM32 Architecture"));
        assertTrue(content.contains("Unknowns, Documentation Gaps & Preliminary Notes"));

        for (String family : EXPECTED_FAMILIES) {
            assertTrue(content.contains(family), "Audit document must discuss " + family);
        }
    }

    @Test
    void capabilityMatrixCoversAllFourFamiliesAndThirtyTwoParts() throws IOException {
        assertTrue(Files.isRegularFile(MATRIX_PATH), "Capability matrix file must exist");
        String json = Files.readString(MATRIX_PATH);

        for (String family : EXPECTED_FAMILIES) {
            assertTrue(json.contains("\"family\": \"" + family + "\""),
                "Matrix must cover family " + family);
        }
        assertTrue(json.contains("\"totalFamilyCount\": 4"));
        assertTrue(json.contains("\"totalExactPartCount\": 32"));
        assertTrue(json.contains("\"schemaId\": \"urn:embedra:schema:stm8-capability-matrix:1\""));
    }

    @Test
    void memoryInvariantsAndVectorTableArchitectureAreEnforced() throws IOException {
        String json = Files.readString(MATRIX_PATH);

        assertTrue(json.contains("\"flashBase\": \"0x008000\""));
        assertTrue(json.contains("\"ramBase\": \"0x000000\""));
        assertTrue(json.contains("\"eepromBase\": \"0x004000\""));
        assertTrue(json.contains("\"optionBytesBase\": \"0x004800\""));
        assertTrue(json.contains("\"peripheralsBase\": \"0x005000\""));
        assertTrue(json.contains("\"peripheralsEnd\": \"0x0057FF\""));
        assertTrue(json.contains("\"bootRomBase\": \"0x006000\""));
        assertTrue(json.contains("\"bootRomEnd\": \"0x0067FF\""));
        assertTrue(json.contains("\"vectorTableBase\": \"0x008000\""));
        assertTrue(json.contains("\"vectorTableSlots\": 32"));
        assertTrue(json.contains("\"vectorEntryBytes\": 4"));
        assertTrue(json.contains("\"vectorOpcode\": \"0x82\""));
        assertTrue(json.contains("\"endianness\": \"BIG_ENDIAN\""));
        assertTrue(json.contains("\"isolatedFromCortexM\": true"));
    }
}
