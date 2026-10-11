package io.github.rezabakhshi.embedra.core.fixture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FixtureManifestJsonParserTest {

    @Test
    void parsesPrimitivesAndEscapes() throws DiagnosticException {
        String json = """
            {
              "boolTrue": true,
              "boolFalse": false,
              "nullVal": null,
              "intPos": 42,
              "intNeg": -100,
              "floatVal": 3.1415,
              "expVal": 1.2e3,
              "expNeg": -2.5E-2,
              "longVal": 3000000000,
              "longNeg": -3000000000,
              "text": "hello \\"world\\" \\\\ \\/ \\b \\f \\n \\r \\t \\u0041",
              "emptyObj": {},
              "emptyArr": []
            }
            """;

        Object parsed = FixtureManifestJsonParser.parse(
                json.getBytes(StandardCharsets.UTF_8),
                ParserLimits.defaults(),
                CancellationToken.none());

        Map<?, ?> map = assertInstanceOf(Map.class, parsed);
        assertEquals(Boolean.TRUE, map.get("boolTrue"));
        assertEquals(Boolean.FALSE, map.get("boolFalse"));
        assertNull(map.get("nullVal"));
        assertEquals(42, map.get("intPos"));
        assertEquals(-100, map.get("intNeg"));
        assertEquals(3.1415, ((Number) map.get("floatVal")).doubleValue(), 0.0001);
        assertEquals(1200.0, ((Number) map.get("expVal")).doubleValue(), 0.0001);
        assertEquals(-0.025, ((Number) map.get("expNeg")).doubleValue(), 0.0001);
        assertEquals(3000000000L, map.get("longVal"));
        assertEquals(-3000000000L, map.get("longNeg"));
        assertEquals("hello \"world\" \\ / \b \f \n \r \t A", map.get("text"));
        assertTrue(((Map<?, ?>) map.get("emptyObj")).isEmpty());
        assertTrue(((List<?>) map.get("emptyArr")).isEmpty());

        // Test carriage return and tab whitespace and consume at EOF
        String crJson = "{\r\n\t \"crVal\": 1\r\n}";
        Object crParsed = FixtureManifestJsonParser.parse(
                crJson.getBytes(StandardCharsets.UTF_8),
                ParserLimits.defaults(),
                CancellationToken.none());
        assertEquals(1, ((Map<?, ?>) crParsed).get("crVal"));

        assertThrows(DiagnosticException.class, () ->
                FixtureManifestJsonParser.parse("{\"a\":".getBytes(StandardCharsets.UTF_8),
                        ParserLimits.defaults(), CancellationToken.none()));

        assertEquals(12.34, ((Number) FixtureManifestJsonParser.parse("12.34".getBytes(StandardCharsets.UTF_8),
                ParserLimits.defaults(), CancellationToken.none())).doubleValue(), 0.0001);
    }

    @Test
    void enforcesParserLimitsAndCancellation() {
        CancellationToken cancelledToken = () -> true;
        assertThrows(DiagnosticException.class, () ->
                FixtureManifestJsonParser.parse("{}".getBytes(StandardCharsets.UTF_8),
                        ParserLimits.defaults(), cancelledToken));

        // Max input bytes
        ParserLimits tinyInput = new ParserLimits(4, 1024, 1024, 100, 10, Duration.ofSeconds(10));
        DiagnosticException exInput = assertThrows(DiagnosticException.class, () ->
                FixtureManifestJsonParser.parse("{\"toolong\":1}".getBytes(StandardCharsets.UTF_8),
                        tinyInput, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, exInput.diagnostic().code());

        // Max allocation bytes
        ParserLimits tinyAlloc = tinyInput.withMaxAllocationBytes(1);
        DiagnosticException exAlloc = assertThrows(DiagnosticException.class, () ->
                FixtureManifestJsonParser.parse("{}".getBytes(StandardCharsets.UTF_8),
                        tinyAlloc, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, exAlloc.diagnostic().code());

        // Max nesting depth
        ParserLimits shallow = new ParserLimits(1024, 1024, 1024, 100, 2, Duration.ofSeconds(10));
        DiagnosticException exDepth = assertThrows(DiagnosticException.class, () ->
                FixtureManifestJsonParser.parse("{\"a\":{\"b\":{\"c\":1}}}".getBytes(StandardCharsets.UTF_8),
                        shallow, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, exDepth.diagnostic().code());

        // Max objects
        ParserLimits fewObjects = new ParserLimits(1024, 1024, 1024, 2, 10, Duration.ofSeconds(10));
        DiagnosticException exObjs = assertThrows(DiagnosticException.class, () ->
                FixtureManifestJsonParser.parse("{\"a\":1,\"b\":2,\"c\":3}".getBytes(StandardCharsets.UTF_8),
                        fewObjects, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, exObjs.diagnostic().code());

        // Max wall time
        ParserLimits fastTimeout = new ParserLimits(1024, 1024, 1024, 100, 10, Duration.ofNanos(1));
        try {
            Thread.sleep(2);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        assertThrows(DiagnosticException.class, () ->
                FixtureManifestJsonParser.parse("{\"a\":1,\"b\":2,\"c\":3}".getBytes(StandardCharsets.UTF_8),
                        fastTimeout, CancellationToken.none()));
    }

    @Test
    void rejectsMalformedJsonForms() {
        List<String> malformed = List.of(
                "",
                "{}",
                "{",
                "}",
                "[]",
                "[",
                "]",
                "\"unterminated",
                "\"line\nbreak\"",
                "\"bad escape \\z\"",
                "\"short unicode \\u00\"",
                "\"bad unicode \\uZZZZ\"",
                "\"cut escape \\",
                "{\"no_colon\" 1}",
                "{\"no_comma\": 1 \"b\": 2}",
                "{123: \"bad_key\"}",
                "[1 2]",
                "trailing {}",
                "true trailing",
                "false trailing",
                "null trailing",
                "123 trailing",
                "truX",
                "falX",
                "nulX",
                "-",
                "-bad",
                "1e",
                "1.e",
                "1e+",
                "+123",
                "{ ",
                "{\"a\"",
                "?unknown");

        for (String form : malformed) {
            if ("{}".equals(form) || "[]".equals(form)) {
                continue;
            }
            assertThrows(DiagnosticException.class, () ->
                    FixtureManifestJsonParser.parse(form.getBytes(StandardCharsets.UTF_8),
                            ParserLimits.defaults(), CancellationToken.none()), form);
        }
    }

    @Test
    void rejectsNonUtf8Input() {
        byte[] nonUtf8 = new byte[] {(byte) 0xC3, (byte) 0x28}; // Invalid UTF-8 sequence
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                FixtureManifestJsonParser.parse(nonUtf8, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.FIXTURE_MANIFEST_INVALID, ex.diagnostic().code());
    }
}
