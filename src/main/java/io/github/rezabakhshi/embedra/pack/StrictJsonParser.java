package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
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

/** Bounded JSON parser for untrusted persisted contracts. */
public final class StrictJsonParser {
    private final String input;

    private final ParserLimits limits;

    private final CancellationToken token;

    private final long startedNanos;

    private int position;

    private long objects;

    private StrictJsonParser(
            String input, ParserLimits limits, CancellationToken token, long startedNanos) {
        this.input = input;
        this.limits = limits;
        this.token = token;
        this.startedNanos = startedNanos;
    }

    public static Object parse(byte[] bytes, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        token.throwIfCancellationRequested();
        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw PackDiagnostics.failure(DiagnosticCode.LIMIT_EXCEEDED,
                "Pack manifest exceeds the configured input limit");
        }
        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        }
        catch (CharacterCodingException exception) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID,
                "Pack manifest is not valid UTF-8");
        }
        StrictJsonParser parser = new StrictJsonParser(decoded, limits, token, System.nanoTime());
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
        return switch (input.charAt(position)) {
            case '{' -> readObject(depth + 1);
            case '[' -> readArray(depth + 1);
            case '"' -> readString();
            case 't' -> readLiteral("true", Boolean.TRUE);
            case 'f' -> readLiteral("false", Boolean.FALSE);
            case 'n' -> readLiteral("null", null);
            default -> readNumber();
        };
    }

    private Map<String, Object> readObject(int depth) throws DiagnosticException {
        checkDepth(depth);
        position++;
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        skipWhitespace();
        if (consume('}')) {
            return result;
        }
        while (true) {
            skipWhitespace();
            if (position >= input.length() || input.charAt(position) != '"') {
                throw invalid("Object key must be a string");
            }
            String key = readString();
            skipWhitespace();
            require(':');
            Object value = readValue(depth);
            if (result.containsKey(key)) {
                throw invalid("Duplicate object key");
            }
            result.put(key, value);
            skipWhitespace();
            if (consume('}')) {
                return result;
            }
            require(',');
        }
    }

    private List<Object> readArray(int depth) throws DiagnosticException {
        checkDepth(depth);
        position++;
        ArrayList<Object> result = new ArrayList<>();
        skipWhitespace();
        if (consume(']')) {
            return result;
        }
        while (true) {
            result.add(readValue(depth));
            skipWhitespace();
            if (consume(']')) {
                return result;
            }
            require(',');
        }
    }

    private String readString() throws DiagnosticException {
        position++;
        StringBuilder result = new StringBuilder();
        while (position < input.length()) {
            char value = input.charAt(position++);
            if (value == '"') {
                return result.toString();
            }
            if (value < 0x20) {
                throw invalid("Control character in JSON string");
            }
            if (value != '\\') {
                result.append(value);
                continue;
            }
            if (position >= input.length()) {
                throw invalid("Incomplete JSON escape");
            }
            char escaped = input.charAt(position++);
            switch (escaped) {
                case '"', '\\', '/' -> result.append(escaped);
                case 'b' -> result.append('\b');
                case 'f' -> result.append('\f');
                case 'n' -> result.append('\n');
                case 'r' -> result.append('\r');
                case 't' -> result.append('\t');
                case 'u' -> result.append(readUnicodeEscape());
                default -> throw invalid("Unsupported JSON escape");
            }
        }
        throw invalid("Unterminated JSON string");
    }

    private char readUnicodeEscape() throws DiagnosticException {
        if (position + 4 > input.length()) {
            throw invalid("Incomplete Unicode escape");
        }
        int value = 0;
        for (int index = 0; index < 4; index++) {
            int digit = Character.digit(input.charAt(position++), 16);
            if (digit < 0) {
                throw invalid("Invalid Unicode escape");
            }
            value = value * 16 + digit;
        }
        return (char) value;
    }

    private Object readLiteral(String literal, Object value) throws DiagnosticException {
        if (!input.startsWith(literal, position)) {
            throw invalid("Invalid JSON literal");
        }
        position += literal.length();
        return value;
    }

    private Long readNumber() throws DiagnosticException {
        int start = position;
        if (consume('-') && position >= input.length()) {
            throw invalid("Incomplete JSON number");
        }
        if (consume('0')) {
            if (position < input.length() && Character.isDigit(input.charAt(position))) {
                throw invalid("Leading zero in JSON number");
            }
        }
        else {
            int digits = 0;
            while (position < input.length() && Character.isDigit(input.charAt(position))) {
                position++;
                digits++;
            }
            if (digits == 0) {
                throw invalid("Invalid JSON value");
            }
        }
        if (position < input.length()
            && (input.charAt(position) == '.' || input.charAt(position) == 'e'
                || input.charAt(position) == 'E')) {
            throw invalid("Pack manifests require integral JSON numbers");
        }
        try {
            return Long.parseLong(input.substring(start, position));
        }
        catch (NumberFormatException exception) {
            throw invalid("JSON integer is out of range");
        }
    }

    private void countObject() throws DiagnosticException {
        objects++;
        if (objects > limits.maxObjects()) {
            throw PackDiagnostics.failure(DiagnosticCode.LIMIT_EXCEEDED,
                "Pack manifest exceeds the configured object limit");
        }
    }

    private void checkDepth(int depth) throws DiagnosticException {
        if (depth > limits.maxNestingDepth()) {
            throw PackDiagnostics.failure(DiagnosticCode.LIMIT_EXCEEDED,
                "Pack manifest exceeds the configured nesting limit");
        }
    }

    private void checkBudget() throws DiagnosticException {
        token.throwIfCancellationRequested();
        if (System.nanoTime() - startedNanos > limits.maxWallTime().toNanos()) {
            throw PackDiagnostics.failure(DiagnosticCode.LIMIT_EXCEEDED,
                "Pack manifest exceeds the configured wall-time limit");
        }
    }

    private void skipWhitespace() {
        while (position < input.length()) {
            char value = input.charAt(position);
            if (value != ' ' && value != '\n' && value != '\r' && value != '\t') {
                return;
            }
            position++;
        }
    }

    private boolean consume(char expected) {
        if (position < input.length() && input.charAt(position) == expected) {
            position++;
            return true;
        }
        return false;
    }

    private void require(char expected) throws DiagnosticException {
        if (!consume(expected)) {
            throw invalid("Expected '" + expected + "'");
        }
    }

    private DiagnosticException invalid(String message) {
        return PackDiagnostics.failure(DiagnosticCode.PACK_MANIFEST_INVALID, message);
    }
}
