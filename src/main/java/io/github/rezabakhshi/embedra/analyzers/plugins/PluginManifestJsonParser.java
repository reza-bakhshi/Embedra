package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bounded JSON parser for untrusted scanner plugin manifests (AN-009).
 */
public final class PluginManifestJsonParser {

    private final String input;

    private final ParserLimits limits;

    private final CancellationToken token;

    private final long startedNanos;

    private int position;

    private long objects;

    private PluginManifestJsonParser(
            String input,
            ParserLimits limits,
            CancellationToken token,
            long startedNanos) {
        this.input = input;
        this.limits = limits;
        this.token = token;
        this.startedNanos = startedNanos;
    }

    /**
     * Parses JSON bytes into Maps, Lists, Strings, Longs, Doubles, and Booleans.
     */
    public static Object parse(
            byte[] bytes,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        token.throwIfCancellationRequested();
        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Plugin manifest exceeds maximum input size", null));
        }

        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID,
                    "Plugin manifest is not valid UTF-8", null));
        }

        PluginManifestJsonParser parser = new PluginManifestJsonParser(
                decoded, limits, token, System.nanoTime());
        Object result = parser.readValue(0);
        parser.skipWhitespace();
        if (parser.position != decoded.length()) {
            throw parser.invalid("Trailing data after JSON value");
        }
        return result;
    }

    private Object readValue(int depth) throws DiagnosticException {
        checkBudget();
        countObject();
        skipWhitespace();
        if (position >= input.length()) {
            throw invalid("Unexpected end of JSON");
        }

        char ch = input.charAt(position);
        if (ch == '{') {
            return readObject(depth);
        }
        if (ch == '[') {
            return readArray(depth);
        }
        if (ch == '"') {
            return readString();
        }
        if (ch == 't' || ch == 'f') {
            return readBoolean();
        }
        if (ch == 'n') {
            return readNull();
        }
        if (ch == '-' || (ch >= '0' && ch <= '9')) {
            return readNumber();
        }
        throw invalid("Unexpected JSON character: " + ch);
    }

    private Map<String, Object> readObject(int depth) throws DiagnosticException {
        if (depth > limits.maxNestingDepth()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED, "Nesting depth exceeded", null));
        }
        match('{');
        skipWhitespace();
        Map<String, Object> map = new LinkedHashMap<>();
        if (consumeIf('}')) {
            return map;
        }
        while (true) {
            checkBudget();
            countObject();
            skipWhitespace();
            String key = readString();
            skipWhitespace();
            match(':');
            skipWhitespace();
            Object value = readValue(depth + 1);
            if (map.put(key, value) != null) {
                throw invalid("Duplicate JSON key: " + key);
            }
            skipWhitespace();
            if (consumeIf('}')) {
                return map;
            }
            match(',');
            skipWhitespace();
        }
    }

    private List<Object> readArray(int depth) throws DiagnosticException {
        if (depth > limits.maxNestingDepth()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED, "Nesting depth exceeded", null));
        }
        match('[');
        skipWhitespace();
        List<Object> list = new ArrayList<>();
        if (consumeIf(']')) {
            return list;
        }
        while (true) {
            checkBudget();
            countObject();
            skipWhitespace();
            list.add(readValue(depth + 1));
            skipWhitespace();
            if (consumeIf(']')) {
                return list;
            }
            match(',');
            skipWhitespace();
        }
    }

    private String readString() throws DiagnosticException {
        match('"');
        StringBuilder sb = new StringBuilder();
        while (position < input.length()) {
            char ch = input.charAt(position++);
            if (ch == '"') {
                return sb.toString();
            }
            if (ch == '\\') {
                if (position >= input.length()) {
                    throw invalid("Unterminated escape sequence");
                }
                char esc = input.charAt(position++);
                switch (esc) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (position + 4 > input.length()) {
                            throw invalid("Truncated unicode escape");
                        }
                        String hex = input.substring(position, position + 4);
                        position += 4;
                        try {
                            sb.append((char) Integer.parseInt(hex, 16));
                        } catch (NumberFormatException e) {
                            throw invalid("Invalid unicode escape: " + hex);
                        }
                    }
                    default -> throw invalid("Unsupported escape: \\" + esc);
                }
            } else if (ch < 0x20) {
                throw invalid("Control character in string");
            } else {
                sb.append(ch);
            }
        }
        throw invalid("Unterminated JSON string");
    }

    private Number readNumber() throws DiagnosticException {
        int start = position;
        boolean isDouble = false;
        if (input.charAt(position) == '-') {
            position++;
        }
        if (position >= input.length() || !Character.isDigit(input.charAt(position))) {
            throw invalid("Invalid number format");
        }
        if (input.charAt(position) == '0' && position + 1 < input.length()
                && Character.isDigit(input.charAt(position + 1))) {
            throw invalid("Leading zeros not allowed in numbers");
        }
        while (position < input.length() && Character.isDigit(input.charAt(position))) {
            position++;
        }
        if (position < input.length() && input.charAt(position) == '.') {
            isDouble = true;
            position++;
            if (position >= input.length() || !Character.isDigit(input.charAt(position))) {
                throw invalid("Number must have digits after decimal point");
            }
            while (position < input.length() && Character.isDigit(input.charAt(position))) {
                position++;
            }
        }
        if (position < input.length() && (input.charAt(position) == 'e' || input.charAt(position) == 'E')) {
            isDouble = true;
            position++;
            if (position < input.length() && (input.charAt(position) == '+' || input.charAt(position) == '-')) {
                position++;
            }
            if (position >= input.length() || !Character.isDigit(input.charAt(position))) {
                throw invalid("Number must have digits in exponent");
            }
            while (position < input.length() && Character.isDigit(input.charAt(position))) {
                position++;
            }
        }

        String raw = input.substring(start, position);
        try {
            if (isDouble) {
                return Double.parseDouble(raw);
            } else {
                return Long.parseLong(raw);
            }
        } catch (NumberFormatException e) {
            throw invalid("Number overflow: " + raw);
        }
    }

    private Boolean readBoolean() throws DiagnosticException {
        if (input.startsWith("true", position)) {
            position += 4;
            return Boolean.TRUE;
        }
        if (input.startsWith("false", position)) {
            position += 5;
            return Boolean.FALSE;
        }
        throw invalid("Invalid boolean literal");
    }

    private Object readNull() throws DiagnosticException {
        if (input.startsWith("null", position)) {
            position += 4;
            return null;
        }
        throw invalid("Invalid null literal");
    }

    private void skipWhitespace() {
        while (position < input.length()) {
            char ch = input.charAt(position);
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
                position++;
            } else {
                break;
            }
        }
    }

    private void match(char expected) throws DiagnosticException {
        if (position >= input.length() || input.charAt(position) != expected) {
            throw invalid("Expected '" + expected + "'");
        }
        position++;
    }

    private boolean consumeIf(char expected) {
        if (position < input.length() && input.charAt(position) == expected) {
            position++;
            return true;
        }
        return false;
    }

    private void checkBudget() throws DiagnosticException {
        token.throwIfCancellationRequested();
        if (System.nanoTime() - startedNanos > limits.maxWallTime().toNanos()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED, "Wall time limit exceeded", null));
        }
    }

    private void countObject() throws DiagnosticException {
        objects++;
        if (objects > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED, "Object count limit exceeded", null));
        }
    }

    private DiagnosticException invalid(String message) {
        return new DiagnosticException(Diagnostic.error(
                DiagnosticCode.PLUGIN_MANIFEST_INVALID, message, null));
    }
}
