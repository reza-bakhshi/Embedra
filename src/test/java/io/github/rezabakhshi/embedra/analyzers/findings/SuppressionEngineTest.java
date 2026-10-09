package io.github.rezabakhshi.embedra.analyzers.findings;

import static io.github.rezabakhshi.embedra.analyzers.findings.SuppressionRule.MatchType.CATEGORY;
import static io.github.rezabakhshi.embedra.analyzers.findings.SuppressionRule.MatchType.FINDING_ID;
import static io.github.rezabakhshi.embedra.analyzers.findings.SuppressionRule.MatchType.TARGET_PATTERN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SuppressionEngineTest {

    private SuppressionEngine engine;

    private UnifiedFinding testFinding1;

    private UnifiedFinding testFinding2;

    private UnifiedFinding testFinding3;

    @BeforeEach
    void setUp() {
        engine = new SuppressionEngine();
        testFinding1 = new UnifiedFinding(
                "TEST-001",
                FindingCategory.SECURITY_LEAD,
                "PASSWORD",
                FindingSeverity.HIGH,
                FindingConfidence.CONFIRMED,
                0.9,
                "ARM",
                0x1000L,
                8,
                "test_pass",
                "Password lead",
                true,
                false,
                null,
                Map.of());

        testFinding2 = new UnifiedFinding(
                "TEST-002",
                FindingCategory.CRYPTOGRAPHY,
                "CRC32",
                FindingSeverity.LOW,
                FindingConfidence.CONFIRMED,
                0.9,
                "ARM",
                0x2000L,
                4,
                "CRC table",
                "CRC32 table",
                false,
                false,
                null,
                Map.of());

        testFinding3 = new UnifiedFinding(
                "TEST-003",
                FindingCategory.LOGGING_DIAGNOSTIC,
                "DEBUG",
                FindingSeverity.INFO,
                FindingConfidence.LIKELY,
                0.7,
                "ARM",
                0x3000L,
                4,
                "debug_printf",
                "Debug print call",
                false,
                false,
                null,
                Map.of());
    }

    @Test
    void matchesById() {
        SuppressionRule rule = SuppressionRule.of("R1", FINDING_ID, "TEST-001", "False positive");
        engine.addRule(rule);

        assertTrue(engine.isSuppressed(testFinding1));
        assertFalse(engine.isSuppressed(testFinding2));
        assertFalse(engine.isSuppressed(testFinding3));

        assertEquals("False positive", engine.getSuppressionReason(testFinding1));
    }

    @Test
    void matchesByTargetExact() {
        SuppressionRule rule = SuppressionRule.of("R2", TARGET_PATTERN, "test_pass", "Known test credential");
        engine.addRule(rule);

        assertTrue(engine.isSuppressed(testFinding1));
        assertFalse(engine.isSuppressed(testFinding2));
    }

    @Test
    void matchesByCategory() {
        SuppressionRule rule = SuppressionRule.of("R3", CATEGORY, "CRYPTOGRAPHY", "Ignore all crypto");
        engine.addRule(rule);

        assertFalse(engine.isSuppressed(testFinding1));
        assertTrue(engine.isSuppressed(testFinding2));
        assertFalse(engine.isSuppressed(testFinding3));
    }

    @Test
    void matchesByRegex() {
        SuppressionRule rule = SuppressionRule.of("R4", TARGET_PATTERN, ".*_printf", "Ignore printf-like calls");
        engine.addRule(rule);

        assertFalse(engine.isSuppressed(testFinding1));
        assertFalse(engine.isSuppressed(testFinding2));
        assertTrue(engine.isSuppressed(testFinding3));
    }

    @Test
    void evaluateBatchAppliesSuppression() {
        SuppressionRule rule = SuppressionRule.of("R1", FINDING_ID, "TEST-001", "False positive");
        engine.addRule(rule);

        List<UnifiedFinding> findings = List.of(testFinding1, testFinding2);
        List<UnifiedFinding> evaluated = engine.evaluate(findings);

        assertEquals(2, evaluated.size());
        assertTrue(evaluated.get(0).suppressed());
        assertEquals("False positive", evaluated.get(0).suppressionReason());
        assertFalse(evaluated.get(1).suppressed());
    }

    @Test
    void removeRuleAndClear() {
        SuppressionRule rule = SuppressionRule.of("R1", FINDING_ID, "TEST-001", "False positive");
        engine.addRule(rule);
        assertEquals(1, engine.getRules().size());

        assertTrue(engine.removeRule("R1"));
        assertEquals(0, engine.getRules().size());
        assertFalse(engine.isSuppressed(testFinding1));

        engine.addRule(rule);
        engine.clearRules();
        assertEquals(0, engine.getRules().size());
    }

    @Test
    void jsonSerializationRoundTrip() {
        SuppressionRule rule1 = SuppressionRule.of("R1", FINDING_ID, "TEST-001", "Reason 1");
        SuppressionRule rule2 = SuppressionRule.of("R2", TARGET_PATTERN, ".*test.*", "Reason 2");
        engine.addRule(rule1);
        engine.addRule(rule2);

        String json = engine.toJson();
        assertNotNull(json);
        assertTrue(json.contains("R1"));
        assertTrue(json.contains("Reason 2"));

        SuppressionEngine loaded = SuppressionEngine.fromJson(json);
        assertEquals(2, loaded.getRules().size());
        assertTrue(loaded.isSuppressed(testFinding1));
    }
}
