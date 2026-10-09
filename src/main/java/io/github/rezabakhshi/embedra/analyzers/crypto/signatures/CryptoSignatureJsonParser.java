package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

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
 * Bounded JSON parser for untrusted cryptographic signature packs (AN-011, CORE-006, CORE-007).
 */
public final class CryptoSignatureJsonParser {

    private final String input;

    private final ParserLimits limits;

    private final CancellationToken token;

    private final long startedNanos;

    private int position;

    private long objects;

    private CryptoSignatureJsonParser(
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
                    "Crypto signature pack exceeds maximum input size", null));
        }

        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException exception) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID,
                    "Crypto signature pack is not valid UTF-8", null));
        }

        CryptoSignatureJsonParser parser = new CryptoSignatureJsonParser(
                decoded, limits, token, System.nanoTime());
        Object result = parser.readValue(0);
        parser.skipWhitespace();
        if (parser.position != decoded.length()) {
            throw parser.invalid("Trailing data after JSON value");
        }
        return result;
    }

    private Object readValue(int depth) throws DiagnosticException {
        token.throwIfCancellationRequested();
        enforceExecutionBudget();
        if (depth > limits.maxNestingDepth()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Nesting depth limit exceeded: " + depth, null));
        }
        skipWhitespace();
        if (position >= input.length()) {
            throw invalid("Unexpected end of input");
        }
        char ch = input.charAt(position);
        return switch (ch) {
            case '{' -> readObject(depth + 1);
            case '[' -> readArray(depth + 1);
            case '"' -> readString();
            case 't', 'f' -> readBoolean();
            case 'n' -> readNull();
            case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' -> readNumber();
            default -> throw invalid("Unexpected character: '" + ch + "'");
        };
    }

    private Map<String, Object> readObject(int depth) throws DiagnosticException {
        consume('{');
        countObject();
        Map<String, Object> map = new LinkedHashMap<>();
        skipWhitespace();
        if (peek('}')) {
            consume('}');
            return map;
        }
        while (true) {
            skipWhitespace();
            if (!peek('"')) {
                throw invalid("Expected string property key");
            }
            String key = readString();
            skipWhitespace();
            consume(':');
            Object value = readValue(depth);
            if (map.put(key, value) != null) {
                throw invalid("Duplicate key: " + key);
            }
            skipWhitespace();
            if (peek('}')) {
                consume('}');
                return map;
            }
            consume(',');
        }
    }

    private List<Object> readArray(int depth) throws DiagnosticException {
        consume('[');
        countObject();
        List<Object> list = new ArrayList<>();
        skipWhitespace();
        if (peek(']')) {
            consume(']');
            return list;
        }
        while (true) {
            list.add(readValue(depth));
            skipWhitespace();
            if (peek(']')) {
                consume(']');
                return list;
            }
            consume(',');
        }
    }

    private String readString() throws DiagnosticException {
        consume('"');
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
                            throw invalid("Incomplete unicode escape");
                        }
                        String hex = input.substring(position, position + 4);
                        position += 4;
                        try {
                            sb.append((char) Integer.parseInt(hex, 16));
                        } catch (NumberFormatException e) {
                            throw invalid("Invalid unicode escape: " + hex);
                        }
                    }
                    default -> throw invalid("Invalid escape character: \\" + esc);
                }
            } else if (ch < 0x20) {
                throw invalid("Unescaped control character in string");
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
        }
        if (input.startsWith("false", position)) {
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
        if (peek('-')) {
            position++;
        }
        while (position < input.length() && Character.isDigit(input.charAt(position))) {
            position++;
        }
        boolean isFloating = false;
        if (position < input.length() && input.charAt(position) == '.') {
            isFloating = true;
            position++;
            while (position < input.length() && Character.isDigit(input.charAt(position))) {
                position++;
            }
        }
        if (position < input.length() && (input.charAt(position) == 'e' || input.charAt(position) == 'E')) {
            isFloating = true;
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
            if (isFloating) {
                return Double.parseDouble(numStr);
            }
            return Long.parseLong(numStr);
        } catch (NumberFormatException e) {
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

    private boolean peek(char ch) {
        return position < input.length() && input.charAt(position) == ch;
    }

    private void consume(char expected) throws DiagnosticException {
        if (position >= input.length() || input.charAt(position) != expected) {
            throw invalid("Expected '" + expected + "' at position " + position);
        }
        position++;
    }

    private void countObject() throws DiagnosticException {
        objects++;
        if (objects > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Too many objects in signature pack", null));
        }
    }

    private void enforceExecutionBudget() throws DiagnosticException {
        if (System.nanoTime() - startedNanos > limits.maxWallTime().toNanos()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Execution budget exceeded during signature parsing", null));
        }
    }

    private DiagnosticException invalid(String message) {
        return new DiagnosticException(Diagnostic.error(
                DiagnosticCode.CRYPTO_SIGNATURE_PACK_INVALID,
                message + " at position " + position, null));
    }
}
