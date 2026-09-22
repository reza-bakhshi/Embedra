package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class StrictJsonParserTest {
    @Test
    void parsesEverySupportedJsonValueAndEscape() throws DiagnosticException {
        String json = """
            {"values":[true,false,null,-2,0,12],"text":"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041"}
            """;

        Object parsed = StrictJsonParser.parse(json.getBytes(StandardCharsets.UTF_8),
            ParserLimits.defaults(), CancellationToken.none());

        Map<?, ?> root = assertInstanceOf(Map.class, parsed);
        assertEquals(Arrays.asList(true, false, null, -2L, 0L, 12L), root.get("values"));
        assertEquals("\"\\/\b\f\n\r\tA", root.get("text"));
    }

    @Test
    void rejectsMalformedJsonFormsWithStableDiagnostic() {
        List<String> malformed = List.of(
            "",
            "{} trailing",
            "{key:1}",
            "{\"a\" 1}",
            "{\"a\":1 \"b\":2}",
            "{\"a\":1,}",
            "[1 2]",
            "[1,]",
            "\"unterminated",
            "\"line\nfeed\"",
            "\"\\",
            "\"\\q\"",
            "\"\\u12\"",
            "\"\\u12xz\"",
            "tru",
            "-",
            "01",
            "1.0",
            "1e2",
            "x",
            "9223372036854775808");

        for (String json : malformed) {
            DiagnosticException exception = assertThrows(DiagnosticException.class,
                () -> StrictJsonParser.parse(json.getBytes(StandardCharsets.UTF_8),
                    ParserLimits.defaults(), CancellationToken.none()), json);
            assertEquals(DiagnosticCode.PACK_MANIFEST_INVALID, exception.diagnostic().code(), json);
        }
    }

    @Test
    void rejectsDuplicateKeysIncludingNullValues() {
        DiagnosticException exception = assertThrows(DiagnosticException.class,
            () -> StrictJsonParser.parse("{\"a\":null,\"a\":1}".getBytes(StandardCharsets.UTF_8),
                ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.PACK_MANIFEST_INVALID, exception.diagnostic().code());
    }
}
