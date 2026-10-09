package io.github.rezabakhshi.embedra.analyzers.plugins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.analyzers.strings.StringProvenance;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

class DeclarativeScannerPluginTest {

    @Test
    void matchesRegexPatternOnStrings() throws Exception {
        DeclarativeRuleDefinition rule = new DeclarativeRuleDefinition(
                "token-scanner",
                "Discovers API tokens",
                DeclarativeMatcherType.REGEX,
                "API_KEY_[0-9A-F]{8}",
                FindingSeverity.HIGH,
                FindingConfidence.CONFIRMED,
                0.90,
                true,
                FindingCategory.SECURITY_LEAD,
                "TOKEN",
                null,
                null
        );

        ScannerPluginManifest manifest = new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                "test.tokens",
                "Token Scanner",
                "1.0.0",
                "Tester",
                "Token scanner description",
                PluginType.DECLARATIVE_RULE,
                "ALL",
                null,
                Set.of(PluginCapability.STRING_SCAN),
                PluginResourceBudget.defaults(),
                List.of(rule)
        );

        DeclarativeScannerPlugin plugin = new DeclarativeScannerPlugin(manifest);

        List<ExtractedString> strings = List.of(
                new ExtractedString(0x1000L, "prefix_API_KEY_1234ABCD_suffix".length(),
                        StringEncoding.ASCII, "prefix_API_KEY_1234ABCD_suffix",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL, true),
                new ExtractedString(0x2000L, "normal unmatching string".length(),
                        StringEncoding.ASCII, "normal unmatching string",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL, true)
        );

        PluginScanContext context = new PluginScanContext(
                new byte[0],
                0L,
                strings,
                Map.of(),
                "ESP32",
                PluginResourceBudget.defaults(),
                CancellationToken.none()
        );

        List<ScannerPluginFinding> findings = plugin.scan(context);

        assertEquals(1, findings.size());
        ScannerPluginFinding f = findings.get(0);
        assertEquals("API_KEY_1234ABCD", f.target());
        assertEquals(0x1000L + 7, f.address());
        assertTrue(f.secret());
        assertEquals("[REDACTED_SECRET]", f.maskedTarget(true));
        assertEquals("API_KEY_1234ABCD", f.maskedTarget(false));
        assertEquals(FindingSeverity.HIGH, f.severity());
    }

    @Test
    void matchesHexBytesOnBinaryBuffer() throws Exception {
        DeclarativeRuleDefinition rule = new DeclarativeRuleDefinition(
                "magic-header",
                "Finds magic payload header",
                DeclarativeMatcherType.HEX_BYTES,
                "de ad be ef",
                FindingSeverity.MEDIUM,
                FindingConfidence.CONFIRMED,
                1.0,
                false,
                FindingCategory.CTF_ENTITY,
                "MAGIC",
                null,
                null
        );

        ScannerPluginManifest manifest = new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                "test.hex",
                "Hex Scanner",
                "1.0.0",
                "Tester",
                "Hex scanner description",
                PluginType.DECLARATIVE_RULE,
                "ALL",
                null,
                Set.of(PluginCapability.BYTE_SCAN),
                PluginResourceBudget.defaults(),
                List.of(rule)
        );

        DeclarativeScannerPlugin plugin = new DeclarativeScannerPlugin(manifest);

        byte[] data = new byte[] {0x00, 0x11, (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, 0x22};
        PluginScanContext context = new PluginScanContext(
                data,
                0x40000000L,
                List.of(),
                Map.of(),
                "ALL",
                PluginResourceBudget.defaults(),
                CancellationToken.none()
        );

        List<ScannerPluginFinding> findings = plugin.scan(context);

        assertEquals(1, findings.size());
        ScannerPluginFinding f = findings.get(0);
        assertEquals(0x40000002L, f.address());
        assertEquals(4, f.length());
        assertEquals("de ad be ef", f.target());
    }

    @Test
    void matchesEntropyWindowOnRandomData() throws Exception {
        DeclarativeRuleDefinition rule = new DeclarativeRuleDefinition(
                "high-entropy",
                "Detects encrypted or compressed blobs",
                DeclarativeMatcherType.ENTROPY,
                "",
                FindingSeverity.MEDIUM,
                FindingConfidence.PLAUSIBLE,
                0.6,
                false,
                FindingCategory.CRYPTOGRAPHY,
                "ENTROPY",
                7.0,
                8.0
        );

        ScannerPluginManifest manifest = new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                "test.entropy",
                "Entropy Scanner",
                "1.0.0",
                "Tester",
                "Entropy description",
                PluginType.DECLARATIVE_RULE,
                "ALL",
                null,
                Set.of(PluginCapability.BYTE_SCAN),
                PluginResourceBudget.defaults(),
                List.of(rule)
        );

        DeclarativeScannerPlugin plugin = new DeclarativeScannerPlugin(manifest);

        // 512 bytes: 256 zeros (entropy 0.0) + 256 random bytes (entropy > 7.5)
        byte[] data = new byte[512];
        Random rnd = new Random(42);
        for (int i = 256; i < 512; i++) {
            data[i] = (byte) rnd.nextInt(256);
        }

        PluginScanContext context = new PluginScanContext(
                data,
                0x1000L,
                List.of(),
                Map.of(),
                "ALL",
                PluginResourceBudget.defaults(),
                CancellationToken.none()
        );

        List<ScannerPluginFinding> findings = plugin.scan(context);

        assertFalse(findings.isEmpty());
        for (ScannerPluginFinding f : findings) {
            assertTrue(f.address() >= 0x1000L + 128);
            assertEquals("ENTROPY", f.subcategory());
        }
    }

    @Test
    void respectsMaxFindingsLimit() throws Exception {
        DeclarativeRuleDefinition rule = new DeclarativeRuleDefinition(
                "byte-match",
                "Matches any 0xAA byte",
                DeclarativeMatcherType.HEX_BYTES,
                "aa",
                FindingSeverity.INFO,
                FindingConfidence.CONFIRMED,
                0.5,
                false,
                FindingCategory.CUSTOM_PLUGIN,
                "MATCH",
                null,
                null
        );

        ScannerPluginManifest manifest = new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                "test.limit",
                "Limit Scanner",
                "1.0.0",
                "Tester",
                "Limit description",
                PluginType.DECLARATIVE_RULE,
                "ALL",
                null,
                Set.of(PluginCapability.BYTE_SCAN),
                PluginResourceBudget.defaults(),
                List.of(rule)
        );

        DeclarativeScannerPlugin plugin = new DeclarativeScannerPlugin(manifest);

        byte[] data = new byte[100];
        java.util.Arrays.fill(data, (byte) 0xaa);

        PluginResourceBudget budget = new PluginResourceBudget(5000, 1024 * 1024, 5);
        PluginScanContext context = new PluginScanContext(
                data,
                0L,
                List.of(),
                Map.of(),
                "ALL",
                budget,
                CancellationToken.none()
        );

        List<ScannerPluginFinding> findings = plugin.scan(context);

        assertEquals(5, findings.size());
    }

    @Test
    void respondsPromptlyToCancellation() {
        DeclarativeRuleDefinition rule = new DeclarativeRuleDefinition(
                "byte-match",
                "Matches bytes",
                DeclarativeMatcherType.HEX_BYTES,
                "ff",
                FindingSeverity.INFO,
                FindingConfidence.CONFIRMED,
                0.5,
                false,
                FindingCategory.CUSTOM_PLUGIN,
                "MATCH",
                null,
                null
        );

        ScannerPluginManifest manifest = new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                "test.cancel",
                "Cancel Scanner",
                "1.0.0",
                "Tester",
                "Cancel description",
                PluginType.DECLARATIVE_RULE,
                "ALL",
                null,
                Set.of(PluginCapability.BYTE_SCAN),
                PluginResourceBudget.defaults(),
                List.of(rule)
        );

        DeclarativeScannerPlugin plugin = new DeclarativeScannerPlugin(manifest);

        PluginScanContext context = new PluginScanContext(
                new byte[1024],
                0L,
                List.of(),
                Map.of(),
                "ALL",
                PluginResourceBudget.defaults(),
                () -> true
        );

        DiagnosticException ex = assertThrows(DiagnosticException.class, () -> plugin.scan(context));
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }
}
