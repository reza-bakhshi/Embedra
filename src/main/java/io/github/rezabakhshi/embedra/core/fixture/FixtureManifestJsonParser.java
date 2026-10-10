package io.github.rezabakhshi.embedra.core.fixture;

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
 * Bounded JSON parser for fixture manifests and evidence indexes (SPEC-12, CORE-006, CORE-007).
 */
public final class FixtureManifestJsonParser {

    private final String input;

    private final ParserLimits limits;

    private final CancellationToken token;

    private final long startedNanos;

    private int position;

    private long objects;

    private FixtureManifestJsonParser(
            String input,
            ParserLimits limits,
            CancellationToken token,
            long startedNanos) {
        this.input = input;
        this.limits = limits;
        this.token = token;
        this.startedNanos = startedNanos;
    }

    public static Object parse(
            byte[] bytes,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        token.throwIfCancellationRequested();
        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Payload exceeds maximum configured input size"));
        }

        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException exception) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_MANIFEST_INVALID,
                    "Manifest is not valid UTF-8"));
        }

        FixtureManifestJsonParser parser = new FixtureManifestJsonParser(
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
        if (depth > limits.maxNestingDepth()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Manifest nesting depth exceeds limit of " + limits.maxNestingDepth()));
        }

        skipWhitespace();
        if (position >= input.length()) {
            throw invalid("Unexpected end of input");
        }

        char ch = input.charAt(position);
        if (ch == '{') {
            return readObject(depth + 1);
        } else if (ch == '[') {
            return readArray(depth + 1);
        } else if (ch == '"') {
            return readString();
        } else if (ch == 't' || ch == 'f') {
            return readBoolean();
        } else if (ch == 'n') {
            return readNull();
        } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
            return readNumber();
        }
        throw invalid("Unexpected character: " + ch);
    }

    private Map<String, Object> readObject(int depth) throws DiagnosticException {
        consume('{');
        Map<String, Object> map = new LinkedHashMap<>();
        skipWhitespace();
        if (peek('}')) {
            consume('}');
            return map;
        }

        while (true) {
            checkBudget();
            skipWhitespace();
            if (!peek('"')) {
                throw invalid("Expected string key in object");
            }
            String key = readString();
            skipWhitespace();
            consume(':');
            Object value = readValue(depth);
            map.put(key, value);
            skipWhitespace();
            if (peek('}')) {
                consume('}');
                break;
            }
            consume(',');
        }
        return map;
    }

    private List<Object> readArray(int depth) throws DiagnosticException {
        consume('[');
        List<Object> list = new ArrayList<>();
        skipWhitespace();
        if (peek(']')) {
            consume(']');
            return list;
        }

        while (true) {
            checkBudget();
            list.add(readValue(depth));
            skipWhitespace();
            if (peek(']')) {
                consume(']');
                break;
            }
            consume(',');
        }
        return list;
    }

    private String readString() throws DiagnosticException {
        consume('"');
        StringBuilder sb = new StringBuilder();
        while (position < input.length()) {
            char ch = input.charAt(position++);
            if (ch == '"') {
                return sb.toString();
            } else if (ch == '\\') {
                if (position >= input.length()) {
                    throw invalid("Unexpected end of escape sequence");
                }
                char escape = input.charAt(position++);
                switch (escape) {
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
                        } catch (NumberFormatException exception) {
                            throw invalid("Invalid unicode escape: " + hex);
                        }
                    }
                    default -> throw invalid("Invalid escape character: " + escape);
                }
            } else if (ch < 0x20) {
                throw invalid("Unescaped control character in string: " + (int) ch);
            } else {
                sb.append(ch);
            }
        }
        throw invalid("Unterminated string");
    }

    private Boolean readBoolean() throws DiagnosticException {
        if (input.startsWith("true", position)) {
            position += 4;
            return Boolean.TRUE;
        } else if (input.startsWith("false", position)) {
            position += 5;
            return Boolean.FALSE;
        }
        throw invalid("Expected boolean literal");
    }

    private Object readNull() throws DiagnosticException {
        if (input.startsWith("null", position)) {
            position += 4;
            return null;
        }
        throw invalid("Expected null literal");
    }

    private Number readNumber() throws DiagnosticException {
        int start = position;
        if (input.charAt(position) == '-') {
            position++;
        }
        while (position < input.length() && Character.isDigit(input.charAt(position))) {
            position++;
        }
        boolean isFloatingPoint = false;
        if (position < input.length() && input.charAt(position) == '.') {
            isFloatingPoint = true;
            position++;
            while (position < input.length() && Character.isDigit(input.charAt(position))) {
                position++;
            }
        }
        if (position < input.length() && (input.charAt(position) == 'e' || input.charAt(position) == 'E')) {
            isFloatingPoint = true;
            position++;
            if (position < input.length() && (input.charAt(position) == '+' || input.charAt(position) == '-')) {
                position++;
            }
            while (position < input.length() && Character.isDigit(input.charAt(position))) {
                position++;
            }
        }
        String numStr = input.substring(start, position);
        try {
            if (isFloatingPoint) {
                return Double.parseDouble(numStr);
            }
            long val = Long.parseLong(numStr);
            if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) {
                return (int) val;
            }
            return val;
        } catch (NumberFormatException exception) {
            throw invalid("Invalid number format: " + numStr);
        }
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

    private boolean peek(char expected) {
        return position < input.length() && input.charAt(position) == expected;
    }

    private void consume(char expected) throws DiagnosticException {
        if (position >= input.length() || input.charAt(position) != expected) {
            throw invalid("Expected '" + expected + "' at position " + position);
        }
        position++;
    }

    private void checkBudget() throws DiagnosticException {
        token.throwIfCancellationRequested();
        objects++;
        if (objects > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "JSON object count exceeded limit of " + limits.maxObjects()));
        }
        long elapsedNanos = System.nanoTime() - startedNanos;
        if (elapsedNanos > limits.maxWallTime().toNanos()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "JSON parsing exceeded time budget of " + limits.maxWallTime().toMillis() + "ms"));
        }
    }

    private DiagnosticException invalid(String message) {
        return new DiagnosticException(Diagnostic.error(
                DiagnosticCode.FIXTURE_MANIFEST_INVALID,
                message + " at position " + position));
    }
}
