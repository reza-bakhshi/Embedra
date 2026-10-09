package io.github.rezabakhshi.embedra.analyzers.yara;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a YARA pattern (string, hex, or regex) used for matching.
 */
public abstract class YaraPattern {
    private final String id;

    protected YaraPattern(String id) {
        this.id = Objects.requireNonNull(id, "id");
    }

    public String id() {
        return id;
    }

    /**
     * Scans the provided byte array for occurrences of this pattern, bounded by maxMatches.
     */
    public abstract List<MatchRange> scan(byte[] data, int maxMatches);

    public record MatchRange(int offset, int length) {
        public MatchRange {
            if (offset < 0 || length <= 0) {
                throw new IllegalArgumentException("Invalid match range: offset=" + offset + ", length=" + length);
            }
        }
    }

    /**
     * A text string pattern supporting ascii, wide, nocase, and fullword modifiers.
     */
    public static final class TextPattern extends YaraPattern {
        private final String text;

        private final boolean ascii;

        private final boolean wide;

        private final boolean nocase;

        private final boolean fullword;

        public TextPattern(String id, String text, boolean ascii, boolean wide, boolean nocase, boolean fullword) {
            super(id);
            this.text = Objects.requireNonNull(text, "text");
            this.ascii = ascii || !wide; // default to ascii if neither specified
            this.wide = wide;
            this.nocase = nocase;
            this.fullword = fullword;
        }

        public String text() {
            return text;
        }

        public boolean isAscii() {
            return ascii;
        }

        public boolean isWide() {
            return wide;
        }

        public boolean isNocase() {
            return nocase;
        }

        public boolean isFullword() {
            return fullword;
        }

        @Override
        public List<MatchRange> scan(byte[] data, int maxMatches) {
            if (data == null || data.length == 0 || text.isEmpty()) {
                return Collections.emptyList();
            }

            List<MatchRange> matches = new ArrayList<>();
            if (ascii) {
                scanBytes(data, text.getBytes(StandardCharsets.ISO_8859_1), matches, maxMatches);
            }
            if (wide && matches.size() < maxMatches) {
                scanBytes(data, text.getBytes(StandardCharsets.UTF_16LE), matches, maxMatches);
            }
            return matches;
        }

        private void scanBytes(byte[] data, byte[] target, List<MatchRange> matches, int maxMatches) {
            int tLen = target.length;
            int limit = data.length - tLen;
            for (int i = 0; i <= limit && matches.size() < maxMatches; i++) {
                if (matchesAt(data, i, target)) {
                    if (!fullword || isWordBoundary(data, i, tLen)) {
                        matches.add(new MatchRange(i, tLen));
                    }
                }
            }
        }

        private boolean matchesAt(byte[] data, int start, byte[] target) {
            for (int j = 0; j < target.length; j++) {
                byte b1 = data[start + j];
                byte b2 = target[j];
                if (nocase) {
                    if (Character.toLowerCase((char) (b1 & 0xFF)) != Character.toLowerCase((char) (b2 & 0xFF))) {
                        return false;
                    }
                } else if (b1 != b2) {
                    return false;
                }
            }
            return true;
        }

        private boolean isWordBoundary(byte[] data, int start, int len) {
            if (start > 0) {
                char prev = (char) (data[start - 1] & 0xFF);
                if (isWordChar(prev)) {
                    return false;
                }
            }
            int end = start + len;
            if (end < data.length) {
                char next = (char) (data[end] & 0xFF);
                if (isWordChar(next)) {
                    return false;
                }
            }
            return true;
        }

        private static boolean isWordChar(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
        }
    }

    /**
     * A hex string pattern with wildcard bytes, nibbles, and bounded jump intervals.
     */
    public static final class HexPattern extends YaraPattern {
        private final List<HexToken> tokens;

        public HexPattern(String id, List<HexToken> tokens) {
            super(id);
            this.tokens = Collections.unmodifiableList(new ArrayList<>(Objects.requireNonNull(tokens, "tokens")));
        }

        public List<HexToken> tokens() {
            return tokens;
        }

        @Override
        public List<MatchRange> scan(byte[] data, int maxMatches) {
            if (data == null || data.length == 0 || tokens.isEmpty()) {
                return Collections.emptyList();
            }

            List<MatchRange> matches = new ArrayList<>();
            for (int i = 0; i < data.length && matches.size() < maxMatches; i++) {
                int matchedLen = matchTokens(data, i, 0);
                if (matchedLen > 0) {
                    matches.add(new MatchRange(i, matchedLen));
                }
            }
            return matches;
        }

        private int matchTokens(byte[] data, int dataIdx, int tokenIdx) {
            if (tokenIdx >= tokens.size()) {
                return 0; // Matched all tokens
            }

            HexToken token = tokens.get(tokenIdx);
            if (token instanceof ByteToken bt) {
                if (dataIdx >= data.length) {
                    return -1;
                }
                int b = data[dataIdx] & 0xFF;
                if ((b & bt.mask) != (bt.value & bt.mask)) {
                    return -1;
                }
                int rest = matchTokens(data, dataIdx + 1, tokenIdx + 1);
                return rest >= 0 ? 1 + rest : -1;
            } else if (token instanceof JumpToken jt) {
                for (int jump = jt.minJump; jump <= jt.maxJump; jump++) {
                    if (dataIdx + jump > data.length) {
                        break;
                    }
                    int rest = matchTokens(data, dataIdx + jump, tokenIdx + 1);
                    if (rest >= 0) {
                        return jump + rest;
                    }
                }
                return -1;
            }
            return -1;
        }
    }

    public sealed interface HexToken permits ByteToken, JumpToken {
    }

    public record ByteToken(int value, int mask) implements HexToken {
        public static ByteToken exact(int value) {
            return new ByteToken(value & 0xFF, 0xFF);
        }

        public static ByteToken wildcard() {
            return new ByteToken(0, 0x00);
        }

        public static ByteToken highNibble(int high) {
            return new ByteToken((high & 0x0F) << 4, 0xF0);
        }

        public static ByteToken lowNibble(int low) {
            return new ByteToken(low & 0x0F, 0x0F);
        }
    }

    public record JumpToken(int minJump, int maxJump) implements HexToken {
        public JumpToken {
            if (minJump < 0 || maxJump < minJump) {
                throw new IllegalArgumentException("Invalid jump range: [" + minJump + "-" + maxJump + "]");
            }
        }

        public static JumpToken fixed(int count) {
            return new JumpToken(count, count);
        }
    }

    /**
     * A regex pattern matching bounded regular expressions.
     */
    public static final class RegexPattern extends YaraPattern {
        private final Pattern pattern;

        public RegexPattern(String id, String regex, boolean nocase, boolean dotAll) {
            super(id);
            int flags = 0;
            if (nocase) {
                flags |= Pattern.CASE_INSENSITIVE;
            }
            if (dotAll) {
                flags |= Pattern.DOTALL;
            }
            this.pattern = Pattern.compile(regex, flags);
        }

        @Override
        public List<MatchRange> scan(byte[] data, int maxMatches) {
            if (data == null || data.length == 0) {
                return Collections.emptyList();
            }

            // Treat raw bytes as Latin-1 string for binary regex scanning
            String text = new String(data, StandardCharsets.ISO_8859_1);
            Matcher matcher = pattern.matcher(text);
            List<MatchRange> matches = new ArrayList<>();
            while (matcher.find() && matches.size() < maxMatches) {
                matches.add(new MatchRange(matcher.start(), matcher.end() - matcher.start()));
            }
            return matches;
        }
    }
}
