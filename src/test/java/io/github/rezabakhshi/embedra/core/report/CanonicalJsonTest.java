package io.github.rezabakhshi.embedra.core.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Arrays;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CanonicalJsonTest {
    @Test
    void sortsObjectKeysAndEscapesStringsDeterministically() {
        HashMap<String, Object> value = new HashMap<>();
        value.put("z", Arrays.asList(true, nullValue(), "line\n\"quote\""));
        value.put("a", 42L);

        assertEquals("{\"a\":42,\"z\":[true,null,\"line\\n\\\"quote\\\"\"]}\n",
            CanonicalJson.write(value));
    }

    @Test
    void rejectsNondeterministicOrNonIntegralValues() {
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(Set.of("a", "b")));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(Map.of("value", 1.5)));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(Map.of(1, "value")));
    }

    @Test
    void supportsEveryIntegralTypeAndJsonEscape() {
        assertEquals("[1,2,3,4,5]\n", CanonicalJson.write(List.of(
            (byte) 1, (short) 2, 3, 4L, BigInteger.valueOf(5))));
        assertEquals("\"\\\\\\b\\f\\r\\t\\u0001\"\n",
            CanonicalJson.write("\\\b\f\r\t\u0001"));
    }

    private static Object nullValue() {
        return null;
    }
}
