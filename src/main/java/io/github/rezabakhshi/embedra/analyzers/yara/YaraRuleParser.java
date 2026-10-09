package io.github.rezabakhshi.embedra.analyzers.yara;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure Java recursive descent parser for YARA rules.
 */
public final class YaraRuleParser {
    private final String source;

    private final ParserLimits limits;

    private int pos;

    private int line;

    private int lineStart;

    public YaraRuleParser(String source) {
        this(source, ParserLimits.defaults());
    }

    public YaraRuleParser(String source, ParserLimits limits) {
        this.source = source != null ? source : "";
        this.limits = limits != null ? limits : ParserLimits.defaults();
        this.pos = 0;
        this.line = 1;
        this.lineStart = 0;
    }

    public static List<YaraRule> parse(String source) throws YaraParseException {
        return new YaraRuleParser(source).parseRules();
    }

    public static List<YaraRule> parse(InputStream in) throws IOException, YaraParseException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String l;
            while ((l = reader.readLine()) != null) {
                sb.append(l).append("\n");
            }
        }
        return parse(sb.toString());
    }

    public List<YaraRule> parseRules() throws YaraParseException {
        List<YaraRule> rules = new ArrayList<>();
        skipWhitespaceAndComments();
        while (pos < source.length()) {
            if (rules.size() >= limits.maxObjects()) {
                throw error("Exceeded maximum allowed rules (" + limits.maxObjects() + ")");
            }
            rules.add(parseRule());
            skipWhitespaceAndComments();
        }
        return rules;
    }

    private YaraRule parseRule() throws YaraParseException {
        expectKeyword("rule");
        String ruleName = parseIdentifier();

        Set<String> tags = new LinkedHashSet<>();
        skipWhitespaceAndComments();
        if (peek() == ':') {
            consume();
            skipWhitespaceAndComments();
            while (isIdentStart(peek())) {
                tags.add(parseIdentifier());
                skipWhitespaceAndComments();
            }
        }

        expect('{');
        Map<String, Object> meta = new LinkedHashMap<>();
        Map<String, YaraPattern> patterns = new LinkedHashMap<>();
        YaraCondition condition = new YaraCondition.TrueCondition();

        skipWhitespaceAndComments();
        while (peek() != '}' && pos < source.length()) {
            String section = parseIdentifier();
            skipWhitespaceAndComments();
            expect(':');
            skipWhitespaceAndComments();

            switch (section) {
                case "meta" -> parseMetaSection(meta);
                case "strings" -> parseStringsSection(patterns);
                case "condition" -> condition = parseCondition();
                default -> throw error("Unexpected section: " + section);
            }
            skipWhitespaceAndComments();
        }
        expect('}');
        return new YaraRule(ruleName, tags, meta, patterns, condition);
    }

    private void parseMetaSection(Map<String, Object> meta) throws YaraParseException {
        skipWhitespaceAndComments();
        while (isIdentStart(peek())) {
            int mark = pos;
            int markLine = line;
            int markLineStart = lineStart;
            String key = parseIdentifier();
            skipWhitespaceAndComments();
            if (peek() == ':') {
                pos = mark;
                line = markLine;
                lineStart = markLineStart;
                break;
            }
            expect('=');
            skipWhitespaceAndComments();

            if (peek() == '"') {
                meta.put(key, parseStringLiteral());
            } else if (peek() == '-' || Character.isDigit(peek())) {
                meta.put(key, parseNumber());
            } else if (isIdentStart(peek())) {
                String ident = parseIdentifier();
                if ("true".equalsIgnoreCase(ident)) {
                    meta.put(key, true);
                } else if ("false".equalsIgnoreCase(ident)) {
                    meta.put(key, false);
                } else {
                    meta.put(key, ident);
                }
            } else {
                throw error("Invalid metadata value for key: " + key);
            }
            skipWhitespaceAndComments();
        }
    }

    private void parseStringsSection(Map<String, YaraPattern> patterns) throws YaraParseException {
        skipWhitespaceAndComments();
        while (peek() == '$') {
            consume();
            String id = "$" + parseIdentifier();
            skipWhitespaceAndComments();
            expect('=');
            skipWhitespaceAndComments();

            char p = peek();
            if (p == '"') {
                patterns.put(id, parseTextPattern(id));
            } else if (p == '{') {
                patterns.put(id, parseHexPattern(id));
            } else if (p == '/') {
                patterns.put(id, parseRegexPattern(id));
            } else {
                throw error("Expected string, hex, or regex pattern for: " + id);
            }
            skipWhitespaceAndComments();
        }
    }

    private YaraPattern.TextPattern parseTextPattern(String id) throws YaraParseException {
        String text = parseStringLiteral();
        boolean ascii = false;
        boolean wide = false;
        boolean nocase = false;
        boolean fullword = false;

        skipWhitespaceAndComments();
        while (isIdentStart(peek())) {
            int mark = pos;
            String mod = parseIdentifier();
            switch (mod) {
                case "ascii" -> ascii = true;
                case "wide" -> wide = true;
                case "nocase" -> nocase = true;
                case "fullword" -> fullword = true;
                default -> {
                    pos = mark;
                    return new YaraPattern.TextPattern(id, text, ascii, wide, nocase, fullword);
                }
            }
            skipWhitespaceAndComments();
        }
        return new YaraPattern.TextPattern(id, text, ascii, wide, nocase, fullword);
    }

    private YaraPattern.HexPattern parseHexPattern(String id) throws YaraParseException {
        expect('{');
        List<YaraPattern.HexToken> tokens = new ArrayList<>();
        skipWhitespaceAndComments();
        while (peek() != '}' && pos < source.length()) {
            if (peek() == '[') {
                tokens.add(parseHexJump());
            } else {
                tokens.add(parseHexByte());
            }
            skipWhitespaceAndComments();
        }
        expect('}');
        return new YaraPattern.HexPattern(id, tokens);
    }

    private YaraPattern.HexToken parseHexJump() throws YaraParseException {
        expect('[');
        skipWhitespaceAndComments();
        long min = parseNumber();
        long max = min;
        skipWhitespaceAndComments();
        if (peek() == '-') {
            consume();
            skipWhitespaceAndComments();
            max = parseNumber();
        }
        expect(']');
        return new YaraPattern.JumpToken((int) min, (int) max);
    }

    private YaraPattern.HexToken parseHexByte() throws YaraParseException {
        char c1 = consume();
        char c2 = consume();
        if (c1 == '?' && c2 == '?') {
            return YaraPattern.ByteToken.wildcard();
        } else if (c1 == '?') {
            int low = parseHexNibble(c2);
            return YaraPattern.ByteToken.lowNibble(low);
        } else if (c2 == '?') {
            int high = parseHexNibble(c1);
            return YaraPattern.ByteToken.highNibble(high);
        } else {
            int val = (parseHexNibble(c1) << 4) | parseHexNibble(c2);
            return YaraPattern.ByteToken.exact(val);
        }
    }

    private int parseHexNibble(char c) throws YaraParseException {
        int d = Character.digit(c, 16);
        if (d < 0) {
            throw error("Invalid hex character: " + c);
        }
        return d;
    }

    private YaraPattern.RegexPattern parseRegexPattern(String id) throws YaraParseException {
        expect('/');
        StringBuilder sb = new StringBuilder();
        while (pos < source.length()) {
            char c = consume();
            if (c == '\\' && pos < source.length()) {
                sb.append(c).append(consume());
            } else if (c == '/') {
                break;
            } else {
                sb.append(c);
            }
        }
        boolean nocase = false;
        skipWhitespaceAndComments();
        if (isIdentStart(peek())) {
            int mark = pos;
            String mod = parseIdentifier();
            if ("nocase".equals(mod)) {
                nocase = true;
            } else {
                pos = mark;
            }
        }
        return new YaraPattern.RegexPattern(id, sb.toString(), nocase, true);
    }

    private YaraCondition parseCondition() throws YaraParseException {
        return parseOrCondition();
    }

    private YaraCondition parseOrCondition() throws YaraParseException {
        YaraCondition left = parseAndCondition();
        skipWhitespaceAndComments();
        while (matchKeyword("or")) {
            skipWhitespaceAndComments();
            YaraCondition right = parseAndCondition();
            left = new YaraCondition.OrCondition(left, right);
            skipWhitespaceAndComments();
        }
        return left;
    }

    private YaraCondition parseAndCondition() throws YaraParseException {
        YaraCondition left = parseUnaryCondition();
        skipWhitespaceAndComments();
        while (matchKeyword("and")) {
            skipWhitespaceAndComments();
            YaraCondition right = parseUnaryCondition();
            left = new YaraCondition.AndCondition(left, right);
            skipWhitespaceAndComments();
        }
        return left;
    }

    private YaraCondition parseUnaryCondition() throws YaraParseException {
        skipWhitespaceAndComments();
        if (matchKeyword("not")) {
            skipWhitespaceAndComments();
            return new YaraCondition.NotCondition(parseUnaryCondition());
        }
        return parsePrimaryCondition();
    }

    private YaraCondition parsePrimaryCondition() throws YaraParseException {
        skipWhitespaceAndComments();
        if (peek() == '(') {
            consume();
            YaraCondition inner = parseCondition();
            skipWhitespaceAndComments();
            expect(')');
            return inner;
        }

        if (peek() == '$') {
            consume();
            String id = "$" + parseIdentifier();
            skipWhitespaceAndComments();
            if (matchKeyword("at")) {
                skipWhitespaceAndComments();
                long off = parseNumber();
                return new YaraCondition.PatternAtCondition(id, off);
            } else if (matchKeyword("in")) {
                skipWhitespaceAndComments();
                expect('(');
                skipWhitespaceAndComments();
                long start = parseNumber();
                skipWhitespaceAndComments();
                expect('.');
                expect('.');
                skipWhitespaceAndComments();
                long end = parseNumber();
                skipWhitespaceAndComments();
                expect(')');
                return new YaraCondition.PatternInCondition(id, start, end);
            }
            return new YaraCondition.PatternMatchCondition(id);
        }

        if (peek() == '#') {
            consume();
            String id = "$" + parseIdentifier();
            skipWhitespaceAndComments();
            YaraCondition.ComparisonOp op = parseComparisonOp();
            skipWhitespaceAndComments();
            long expected = parseNumber();
            return new YaraCondition.PatternCountCondition(id, op, (int) expected);
        }

        if (matchKeyword("any")) {
            skipWhitespaceAndComments();
            expectKeyword("of");
            skipWhitespaceAndComments();
            return parseSetTarget(1, false);
        }

        if (matchKeyword("all")) {
            skipWhitespaceAndComments();
            expectKeyword("of");
            skipWhitespaceAndComments();
            return parseSetTarget(0, true);
        }

        if (Character.isDigit(peek())) {
            long count = parseNumber();
            skipWhitespaceAndComments();
            if (matchKeyword("of")) {
                skipWhitespaceAndComments();
                return parseSetTarget((int) count, false);
            }
        }

        if (matchKeyword("true")) {
            return new YaraCondition.TrueCondition();
        }
        if (matchKeyword("false")) {
            return new YaraCondition.FalseCondition();
        }

        throw error("Unexpected token in condition: '" + peek() + "'");
    }

    private YaraCondition parseSetTarget(int count, boolean all) throws YaraParseException {
        if (matchKeyword("them")) {
            return all ? YaraCondition.SetCondition.allThem()
                : (count == 1 ? YaraCondition.SetCondition.anyThem() : YaraCondition.SetCondition.countThem(count));
        }

        expect('(');
        List<String> patterns = new ArrayList<>();
        skipWhitespaceAndComments();
        while (peek() == '$') {
            consume();
            patterns.add("$" + parseIdentifier());
            skipWhitespaceAndComments();
            if (peek() == ',') {
                consume();
                skipWhitespaceAndComments();
            }
        }
        expect(')');
        return all ? YaraCondition.SetCondition.allOf(patterns)
            : (count == 1 ? YaraCondition.SetCondition.anyOf(patterns)
            : YaraCondition.SetCondition.countOf(count, patterns));
    }

    private YaraCondition.ComparisonOp parseComparisonOp() throws YaraParseException {
        if (match("==")) {
            return YaraCondition.ComparisonOp.EQ;
        }
        if (match("!=")) {
            return YaraCondition.ComparisonOp.NE;
        }
        if (match(">=")) {
            return YaraCondition.ComparisonOp.GTE;
        }
        if (match("<=")) {
            return YaraCondition.ComparisonOp.LTE;
        }
        if (match(">")) {
            return YaraCondition.ComparisonOp.GT;
        }
        if (match("<")) {
            return YaraCondition.ComparisonOp.LT;
        }
        throw error("Expected comparison operator (==, !=, >, <, >=, <=)");
    }

    private String parseStringLiteral() throws YaraParseException {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (pos < source.length()) {
            char c = consume();
            if (c == '"') {
                return sb.toString();
            } else if (c == '\\' && pos < source.length()) {
                char esc = consume();
                switch (esc) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case '\\' -> sb.append('\\');
                    case '"' -> sb.append('"');
                    case 'x' -> {
                        int h1 = parseHexNibble(consume());
                        int h2 = parseHexNibble(consume());
                        sb.append((char) ((h1 << 4) | h2));
                    }
                    default -> sb.append(esc);
                }
            } else {
                sb.append(c);
            }
        }
        throw error("Unterminated string literal");
    }

    private long parseNumber() throws YaraParseException {
        skipWhitespaceAndComments();
        boolean neg = false;
        if (peek() == '-') {
            consume();
            neg = true;
        }
        int start = pos;
        if (peek() == '0' && (pos + 1 < source.length()) && (source.charAt(pos + 1) == 'x'
                || source.charAt(pos + 1) == 'X')) {
            consume();
            consume();
            while (pos < source.length() && Character.digit(peek(), 16) >= 0) {
                consume();
            }
            long val = Long.parseLong(source.substring(start + 2, pos), 16);
            return neg ? -val : val;
        }

        while (pos < source.length() && Character.isDigit(peek())) {
            consume();
        }
        if (pos == start) {
            throw error("Expected number");
        }
        long val = Long.parseLong(source.substring(start, pos));
        if (matchKeyword("KB")) {
            val *= 1024L;
        } else if (matchKeyword("MB")) {
            val *= 1024L * 1024L;
        }
        return neg ? -val : val;
    }

    private String parseIdentifier() throws YaraParseException {
        skipWhitespaceAndComments();
        int start = pos;
        if (!isIdentStart(peek())) {
            throw error("Expected identifier, got '" + peek() + "'");
        }
        while (pos < source.length() && isIdentPart(peek())) {
            consume();
        }
        return source.substring(start, pos);
    }

    private boolean matchKeyword(String kw) {
        int mark = pos;
        if (source.startsWith(kw, pos)) {
            int nextPos = pos + kw.length();
            if (nextPos >= source.length() || !isIdentPart(source.charAt(nextPos))) {
                pos = nextPos;
                return true;
            }
        }
        pos = mark;
        return false;
    }

    private void expectKeyword(String kw) throws YaraParseException {
        if (!matchKeyword(kw)) {
            throw error("Expected keyword '" + kw + "'");
        }
    }

    private boolean match(String str) {
        if (source.startsWith(str, pos)) {
            pos += str.length();
            return true;
        }
        return false;
    }

    private void expect(char c) throws YaraParseException {
        if (peek() != c) {
            throw error("Expected '" + c + "', got '" + peek() + "'");
        }
        consume();
    }

    private char peek() {
        return pos < source.length() ? source.charAt(pos) : '\0';
    }

    private char consume() {
        if (pos >= source.length()) {
            return '\0';
        }
        char c = source.charAt(pos++);
        if (c == '\n') {
            line++;
            lineStart = pos;
        }
        return c;
    }

    private void skipWhitespaceAndComments() throws YaraParseException {
        while (pos < source.length()) {
            char c = peek();
            if (Character.isWhitespace(c)) {
                consume();
            } else if (c == '/' && pos + 1 < source.length()) {
                char next = source.charAt(pos + 1);
                if (next == '/') {
                    while (pos < source.length() && peek() != '\n') {
                        consume();
                    }
                } else if (next == '*') {
                    consume();
                    consume();
                    boolean closed = false;
                    while (pos + 1 < source.length()) {
                        if (peek() == '*' && source.charAt(pos + 1) == '/') {
                            consume();
                            consume();
                            closed = true;
                            break;
                        }
                        consume();
                    }
                    if (!closed) {
                        throw error("Unterminated comment");
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    private static boolean isIdentStart(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    }

    private static boolean isIdentPart(char c) {
        return isIdentStart(c) || (c >= '0' && c <= '9');
    }

    private YaraParseException error(String message) {
        return new YaraParseException(message, line, pos - lineStart + 1);
    }
}
