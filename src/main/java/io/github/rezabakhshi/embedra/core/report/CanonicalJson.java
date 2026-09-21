package io.github.rezabakhshi.embedra.core.report;

import java.math.BigInteger;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Minimal deterministic JSON encoder for canonical report value trees. */
public final class CanonicalJson {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private CanonicalJson() {
    }

    public static String write(Object value) {
        StringBuilder output = new StringBuilder();
        append(value, output);
        return output.append('\n').toString();
    }

    private static void append(Object value, StringBuilder output) {
        if (value == null) {
            output.append("null");
        }
        else if (value instanceof String text) {
            appendString(text, output);
        }
        else if (value instanceof Boolean bool) {
            output.append(bool);
        }
        else if (isIntegralNumber(value)) {
            output.append(value);
        }
        else if (value instanceof Map<?, ?> map) {
            appendMap(map, output);
        }
        else if (value instanceof Set<?>) {
            throw new IllegalArgumentException("Sets are not canonical JSON sequences; sort them explicitly");
        }
        else if (value instanceof Iterable<?> iterable) {
            appendIterable(iterable, output);
        }
        else {
            throw new IllegalArgumentException("Unsupported canonical JSON value: " + value.getClass().getName());
        }
    }

    private static boolean isIntegralNumber(Object value) {
        return value instanceof Byte || value instanceof Short || value instanceof Integer
            || value instanceof Long || value instanceof BigInteger;
    }

    private static void appendMap(Map<?, ?> map, StringBuilder output) {
        List<Map.Entry<String, Object>> entries = new ArrayList<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("Canonical JSON object keys must be strings");
            }
            entries.add(new AbstractMap.SimpleImmutableEntry<>(key, entry.getValue()));
        }
        entries.sort(Comparator.comparing(Map.Entry::getKey));
        output.append('{');
        for (int index = 0; index < entries.size(); index++) {
            if (index != 0) {
                output.append(',');
            }
            Map.Entry<String, Object> entry = entries.get(index);
            appendString(entry.getKey(), output);
            output.append(':');
            append(entry.getValue(), output);
        }
        output.append('}');
    }

    private static void appendIterable(Iterable<?> iterable, StringBuilder output) {
        output.append('[');
        boolean first = true;
        for (Object item : iterable) {
            if (!first) {
                output.append(',');
            }
            append(item, output);
            first = false;
        }
        output.append(']');
    }

    private static void appendString(String value, StringBuilder output) {
        output.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> appendUnescapedOrUnicode(character, output);
            }
        }
        output.append('"');
    }

    private static void appendUnescapedOrUnicode(char character, StringBuilder output) {
        if (character >= 0x20) {
            output.append(character);
            return;
        }
        output.append("\\u");
        output.append(HEX[(character >>> 12) & 0xf]);
        output.append(HEX[(character >>> 8) & 0xf]);
        output.append(HEX[(character >>> 4) & 0xf]);
        output.append(HEX[character & 0xf]);
    }
}
